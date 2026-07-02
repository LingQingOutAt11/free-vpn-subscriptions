// Package main provides the fnctl CLI — entry point for the aggregator.
//
// The only relevant command is `aggregate`: it fetches every enabled source,
// probes every node for TCP reachability, deduplicates and ranks the alive
// set, resolves each node's country via GeoIP, and writes output files
// (clash.yaml, singbox.json, v2ray-base64.txt, per-country variants,
// status.json) plus a generated README.md.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Au1rxx/free-vpn-subscriptions/internal/aggregate"
	"github.com/Au1rxx/free-vpn-subscriptions/internal/config"
	"github.com/Au1rxx/free-vpn-subscriptions/internal/discover"
	"github.com/Au1rxx/free-vpn-subscriptions/internal/geoip"
	"github.com/Au1rxx/free-vpn-subscriptions/internal/pages"
	"github.com/Au1rxx/free-vpn-subscriptions/internal/readme"
	"github.com/Au1rxx/free-vpn-subscriptions/internal/sources"
	"github.com/Au1rxx/free-vpn-subscriptions/internal/verify"
	"github.com/Au1rxx/free-vpn-subscriptions/pkg/emit"
	"github.com/Au1rxx/free-vpn-subscriptions/pkg/node"
	"github.com/Au1rxx/free-vpn-subscriptions/pkg/probe"
)

// runDeadline caps a single aggregate run. The hourly cron has a hard 6h
// GitHub Actions ceiling; we aim to finish well inside that so SIGINT from
// the runner cleanly aborts in-flight probes instead of leaving goroutines
// to be killed.
const runDeadline = 30 * time.Minute

var cfgPath string

func main() {
	root := &cobra.Command{
		Use:   "fnctl",
		Short: "free-vpn-subscriptions aggregator CLI",
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "config.yaml", "path to configuration file")
	root.AddCommand(newAggregateCmd())
	root.AddCommand(newDiscoverSourcesCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newAggregateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "aggregate",
		Short: "Fetch, probe, rank, and emit subscription outputs",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				die(err)
			}

			ctx, cancel := signal.NotifyContext(
				context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			ctx, cancelDeadline := context.WithTimeout(ctx, runDeadline)
			defer cancelDeadline()

			fetched := fetchAll(ctx, cfg)
			fmt.Printf("fetched %d nodes from %d sources\n", len(fetched), countEnabled(cfg.Sources))

			alive := probe.TCP(ctx, fetched,
				time.Duration(cfg.Probe.TimeoutMS)*time.Millisecond,
				cfg.Probe.Concurrency)
			fmt.Printf("alive %d / %d after TCP probe\n", len(alive), len(fetched))

			if cfg.Probe.TLSVerify {
				before := len(alive)
				alive = probe.TLS(ctx, alive,
					time.Duration(cfg.Probe.TimeoutMS)*time.Millisecond,
					cfg.Probe.Concurrency)
				fmt.Printf("alive %d / %d after TLS handshake\n", len(alive), before)
			}

			// HTTP-over-proxy verification — this is where we move from
			// "TCP/TLS handshake succeeded" to "traffic actually flows
			// through the proxy". Sort by RTT first so the pool picks
			// the fastest TLS-alive nodes.
			verified := alive
			if cfg.Verify.Enabled {
				sortByLatency(alive)
				before := len(alive)
				verified = verify.Run(ctx, alive, verify.Config{
					Enabled:        cfg.Verify.Enabled,
					CandidatePool:  cfg.Verify.CandidatePool,
					BatchSize:      cfg.Verify.BatchSize,
					BasePort:       cfg.Verify.BasePort,
					Concurrency:    cfg.Verify.Concurrency,
					TimeoutMS:      cfg.Verify.TimeoutMS,
					Rounds:         cfg.Verify.Rounds,
					RoundGapMS:     cfg.Verify.RoundGapMS,
					Targets:        cfg.Verify.Targets,
					SingBoxBin:     cfg.Verify.SingBoxBin,
					StartupTimeout: time.Duration(cfg.Verify.StartupTimeoutMS) * time.Millisecond,
				})
				fmt.Printf("verified %d / %d after HTTP-over-proxy probe\n", len(verified), before)
			}

			enrichGeoIP(cfg, verified)

			selected, summary := aggregate.Run(verified, cfg.Aggregate)
			summary.TotalAlive = len(alive)
			summary.TotalVerified = len(verified)
			summary.TotalFetched = len(fetched)
			summary.GeneratedAtUnix = time.Now().Unix()
			summary.ByCountry = countByCountry(selected)
			fmt.Printf("selected %d nodes\n", len(selected))

			if err := writeOutputs(cfg, selected, summary); err != nil {
				die(err)
			}
			fmt.Println("outputs written to", cfg.Output.Dir)
		},
	}
}

func newDiscoverSourcesCmd() *cobra.Command {
	var (
		outYAML  string
		outMD    string
		perQuery int
	)
	cmd := &cobra.Command{
		Use:   "discover-sources",
		Short: "Search GitHub for new public source candidates and write a report",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				die(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			report, err := discover.Run(ctx, cfg, discover.Options{
				Token:         os.Getenv("GITHUB_TOKEN"),
				PerQuery:      perQuery,
				ExistingURLs:  discover.ExistingURLs(cfg),
				ExistingNames: discover.ExistingNames(cfg),
			})
			if err != nil {
				die(err)
			}

			if err := os.MkdirAll(filepath.Dir(outYAML), 0o755); err != nil {
				die(err)
			}
			if err := discover.WriteYAML(outYAML, report); err != nil {
				die(err)
			}
			if err := discover.WriteMarkdown(outMD, report); err != nil {
				die(err)
			}
			fmt.Printf("discovered %d candidates across %d repos\n", len(report.Candidates), report.SearchedRepos)
			fmt.Println("reports written to", outYAML, "and", outMD)
		},
	}
	cmd.Flags().StringVar(&outYAML, "output", "output/discovered-sources.yaml", "path to YAML discovery report")
	cmd.Flags().StringVar(&outMD, "markdown", "output/discovered-sources.md", "path to Markdown discovery report")
	cmd.Flags().IntVar(&perQuery, "per-query", 15, "GitHub repositories to inspect per search query")
	return cmd
}

// fetchAll fans out one goroutine per enabled source. Each fetch honors the
// passed context so an upstream deadline (or SIGINT) aborts in-flight HTTP.
func fetchAll(ctx context.Context, cfg *config.Config) []*node.Node {
	timeout := time.Duration(cfg.Probe.TimeoutMS*4) * time.Millisecond
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		all []*node.Node
	)
	for _, s := range cfg.Sources {
		if !s.Enabled {
			continue
		}
		wg.Add(1)
		go func(src config.Source) {
			defer wg.Done()
			nodes, err := sources.Fetch(ctx, src, timeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  [skip] %s: %v\n", src.Name, err)
				return
			}
			if cfg.Probe.MaxNodesPerSource > 0 && len(nodes) > cfg.Probe.MaxNodesPerSource {
				nodes = nodes[:cfg.Probe.MaxNodesPerSource]
			}
			fmt.Fprintf(os.Stderr, "  [ok]   %s: %d nodes\n", src.Name, len(nodes))
			mu.Lock()
			all = append(all, nodes...)
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return all
}

// enrichGeoIP populates n.Country on every node. Soft-failures on DB/open so
// the pipeline still produces global outputs even without country tags.
func enrichGeoIP(cfg *config.Config, nodes []*node.Node) {
	if !cfg.GeoIP.Enabled {
		return
	}
	if err := geoip.EnsureDB(cfg.GeoIP.DBURL, cfg.GeoIP.DBPath); err != nil {
		fmt.Fprintf(os.Stderr, "  [warn] geoip db: %v\n", err)
		return
	}
	r, err := geoip.Open(cfg.GeoIP.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [warn] geoip open: %v\n", err)
		return
	}
	defer r.Close()
	r.Enrich(nodes, 50)
	fmt.Fprintf(os.Stderr, "  [ok]   geoip enriched %d nodes\n", len(nodes))
}

// sortByLatency orders nodes ascending by LatencyMS in-place. Used before
// verify so the candidate pool is the fastest TLS-alive subset — faster
// nodes are both more likely to pass HTTP verification and more valuable
// to publish.
func sortByLatency(nodes []*node.Node) {
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].LatencyMS < nodes[j].LatencyMS
	})
}

func countEnabled(srcs []config.Source) int {
	n := 0
	for _, s := range srcs {
		if s.Enabled {
			n++
		}
	}
	return n
}

func countByCountry(ns []*node.Node) map[string]int {
	m := map[string]int{}
	for _, n := range ns {
		cc := n.Country
		if cc == "" {
			cc = "XX"
		}
		m[cc]++
	}
	return m
}

func writeOutputs(cfg *config.Config, selected []*node.Node, summary aggregate.Summary) error {
	outDir := cfg.Output.Dir
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	if err := emitSet(cfg, outDir, "", selected); err != nil {
		return err
	}
	if err := writeIPExports(outDir, selected, summary.GeneratedAtUnix); err != nil {
		return err
	}

	// Per-country outputs: one set per country with ≥ MinPerCountry nodes.
	if cfg.GeoIP.Enabled && cfg.GeoIP.MinPerCountry > 0 {
		byCC := groupByCountry(selected)
		countryDir := filepath.Join(outDir, "by-country")
		// Wipe stale per-country files so dropped countries don't linger.
		_ = os.RemoveAll(countryDir)
		if err := os.MkdirAll(countryDir, 0o755); err != nil {
			return err
		}
		for _, cc := range sortedCountries(byCC) {
			nodes := byCC[cc]
			if len(nodes) < cfg.GeoIP.MinPerCountry {
				continue
			}
			if err := emitSet(cfg, countryDir, cc, nodes); err != nil {
				return fmt.Errorf("emit %s: %w", cc, err)
			}
		}
	}

	statusJSON, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("status marshal: %w", err)
	}
	if err := write(filepath.Join(outDir, "status.json"), string(statusJSON)); err != nil {
		return err
	}

	input := readme.Input{
		Title:          cfg.Readme.Title,
		RepoURL:        cfg.Readme.RepoURL,
		Nodes:          selected,
		Summary:        summary,
		MinPerCountry:  cfg.GeoIP.MinPerCountry,
		CountryEnabled: cfg.GeoIP.Enabled,
	}
	for _, loc := range readme.Locales() {
		if err := write(loc.FileName, readme.Generate(input, loc)); err != nil {
			return fmt.Errorf("readme %s: %w", loc.FileName, err)
		}
	}

	if cfg.Output.Pages.Enabled {
		if err := pages.Generate(pages.Input{
			Title:         cfg.Readme.Title,
			RepoURL:       cfg.Readme.RepoURL,
			SiteURL:       cfg.Output.Pages.SiteURL,
			Summary:       summary,
			Selected:      selected,
			MinPerCountry: cfg.GeoIP.MinPerCountry,
		}, cfg.Output.Pages.Dir); err != nil {
			return fmt.Errorf("pages: %w", err)
		}
	}

	return nil
}

type ipExport struct {
	GeneratedAtUnix int64         `json:"generated_at_unix"`
	TotalSelected   int           `json:"total_selected"`
	UniqueIPs       int           `json:"unique_ips"`
	IPs             []ipExportRow `json:"ips"`
}

type ipExportRow struct {
	IP        string            `json:"ip"`
	Countries []string          `json:"countries,omitempty"`
	Ports     []int             `json:"ports"`
	Nodes     []ipExportNodeRef `json:"nodes"`
}

type ipExportNodeRef struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
	Country    string `json:"country,omitempty"`
	SourceName string `json:"source_name,omitempty"`
	LatencyMS  int    `json:"latency_ms,omitempty"`
}

func writeIPExports(dir string, nodes []*node.Node, generatedAtUnix int64) error {
	byIP := map[string][]*node.Node{}
	for _, n := range nodes {
		if n.Server == "" {
			continue
		}
		byIP[n.Server] = append(byIP[n.Server], n)
	}

	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPStrings(ips[i], ips[j]) < 0
	})

	lines := make([]string, 0, len(ips))
	payload := ipExport{
		GeneratedAtUnix: generatedAtUnix,
		TotalSelected:   len(nodes),
		UniqueIPs:       len(ips),
		IPs:             make([]ipExportRow, 0, len(ips)),
	}
	for _, ip := range ips {
		lines = append(lines, ip)
		group := byIP[ip]
		sort.Slice(group, func(i, j int) bool {
			if group[i].LatencyMS == group[j].LatencyMS {
				if group[i].Port == group[j].Port {
					return group[i].Name < group[j].Name
				}
				return group[i].Port < group[j].Port
			}
			return group[i].LatencyMS < group[j].LatencyMS
		})

		countries := make([]string, 0, len(group))
		ports := make([]int, 0, len(group))
		seenCountry := map[string]bool{}
		seenPort := map[int]bool{}
		row := ipExportRow{
			IP:    ip,
			Nodes: make([]ipExportNodeRef, 0, len(group)),
		}
		for _, n := range group {
			if n.Country != "" && !seenCountry[n.Country] {
				seenCountry[n.Country] = true
				countries = append(countries, n.Country)
			}
			if !seenPort[n.Port] {
				seenPort[n.Port] = true
				ports = append(ports, n.Port)
			}
			row.Nodes = append(row.Nodes, ipExportNodeRef{
				Name:       n.Name,
				Protocol:   n.Protocol,
				Port:       n.Port,
				Country:    n.Country,
				SourceName: n.SourceName,
				LatencyMS:  n.LatencyMS,
			})
		}
		sort.Strings(countries)
		sort.Ints(ports)
		row.Countries = countries
		row.Ports = ports
		payload.IPs = append(payload.IPs, row)
	}

	if err := write(filepath.Join(dir, "ips.txt"), joinLines(lines)); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("ips marshal: %w", err)
	}
	return write(filepath.Join(dir, "ips.json"), string(raw))
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	out := lines[0]
	for _, line := range lines[1:] {
		out += "\n" + line
	}
	return out + "\n"
}

func compareIPStrings(a, b string) int {
	aa, oka := splitIPv4(a)
	bb, okb := splitIPv4(b)
	if oka && okb {
		for i := range aa {
			if aa[i] < bb[i] {
				return -1
			}
			if aa[i] > bb[i] {
				return 1
			}
		}
		return 0
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func splitIPv4(s string) ([4]int, bool) {
	var out [4]int
	part := ""
	idx := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if idx > 3 || part == "" {
				return out, false
			}
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n > 255 {
				return out, false
			}
			out[idx] = n
			idx++
			part = ""
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return out, false
		}
		part += string(s[i])
	}
	if idx != 3 || part == "" {
		return out, false
	}
	n, err := strconv.Atoi(part)
	if err != nil || n < 0 || n > 255 {
		return out, false
	}
	out[3] = n
	return out, true
}

// emitSet writes clash / singbox / v2ray-base64 files for the given node list.
// When suffix is empty, files are named clash.yaml / singbox.json / v2ray-base64.txt.
// When suffix is non-empty (e.g. "HK"), files are named clash-HK.yaml etc.
func emitSet(cfg *config.Config, dir, suffix string, nodes []*node.Node) error {
	formats := map[string]bool{}
	for _, f := range cfg.Output.Formats {
		formats[f] = true
	}
	tag := ""
	if suffix != "" {
		tag = "-" + suffix
	}

	if formats["clash"] {
		content, err := emit.Clash(nodes)
		if err != nil {
			return fmt.Errorf("clash: %w", err)
		}
		if err := write(filepath.Join(dir, "clash"+tag+".yaml"), content); err != nil {
			return err
		}
	}
	if formats["singbox"] {
		content, err := emit.Singbox(nodes)
		if err != nil {
			return fmt.Errorf("singbox: %w", err)
		}
		if err := write(filepath.Join(dir, "singbox"+tag+".json"), content); err != nil {
			return err
		}
	}
	if formats["v2ray-base64"] {
		if err := write(filepath.Join(dir, "v2ray-base64"+tag+".txt"),
			emit.V2RayBase64(nodes)); err != nil {
			return err
		}
	}
	return nil
}

func groupByCountry(ns []*node.Node) map[string][]*node.Node {
	m := map[string][]*node.Node{}
	for _, n := range ns {
		cc := n.Country
		if cc == "" {
			continue // skip unknown — no point publishing an "XX" bucket
		}
		m[cc] = append(m[cc], n)
	}
	return m
}

func sortedCountries(m map[string][]*node.Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func write(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
