package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Au1rxx/free-vpn-subscriptions/internal/config"
	"github.com/Au1rxx/free-vpn-subscriptions/pkg/parse"
)

const (
	defaultPerQuery    = 15
	defaultHTTPTimeout = 15 * time.Second
	maxProbeBytes      = 256 * 1024
)

var (
	searchQueries = []string{
		"v2ray-configs in:name,description,readme",
		"free proxy clash in:name,description,readme",
		"proxy collector subscription in:name,description,readme",
		"clash subscription in:name,description,readme",
	}
	commonPaths = []string{
		"All_Configs_Sub.txt",
		"all_configs.txt",
		"All.txt",
		"Config_jo.txt",
		"V2RAY_RAW.txt",
		"all/clash.yaml",
		"clash.yaml",
		"clash/clash.provider.yaml",
		"mix.txt",
		"mix_clash.yaml",
		"source/clash-meta-2.yaml",
		"sub.yaml",
		"sub/proxies.txt",
		"sub/sub_merge.txt",
		"subscriptions/v2ray/super-sub.txt",
		"Eternity.txt",
	}
)

type Options struct {
	Token         string
	PerQuery      int
	ExistingURLs  map[string]bool
	ExistingNames map[string]bool
}

type Report struct {
	GeneratedAt     time.Time   `yaml:"generated_at"`
	SearchedRepos   int         `yaml:"searched_repos"`
	SkippedExisting int         `yaml:"skipped_existing"`
	Candidates      []Candidate `yaml:"candidates"`
}

type Candidate struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	Format      string `yaml:"format"`
	Enabled     bool   `yaml:"enabled"`
	Repo        string `yaml:"repo"`
	Branch      string `yaml:"branch"`
	Path        string `yaml:"path"`
	Query       string `yaml:"query"`
	ParsedNodes int    `yaml:"parsed_nodes"`
	PushedAt    string `yaml:"pushed_at,omitempty"`
}

type repoSearchResponse struct {
	Items []repoItem `json:"items"`
}

type repoItem struct {
	FullName      string `json:"full_name"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	PushedAt      string `json:"pushed_at"`
}

func Run(ctx context.Context, cfg *config.Config, opts Options) (Report, error) {
	if opts.PerQuery <= 0 {
		opts.PerQuery = defaultPerQuery
	}

	client := &http.Client{Timeout: defaultHTTPTimeout}
	seenRepos := map[string]bool{}
	seenURLs := cloneSet(opts.ExistingURLs)
	seenNames := cloneSet(opts.ExistingNames)
	report := Report{GeneratedAt: time.Now().UTC()}

	for _, query := range searchQueries {
		repos, err := searchRepos(ctx, client, opts.Token, query, opts.PerQuery)
		if err != nil {
			return Report{}, err
		}
		for _, repo := range repos {
			if seenRepos[repo.FullName] {
				continue
			}
			seenRepos[repo.FullName] = true
			report.SearchedRepos++

			candidate, found, skipped, err := probeRepo(ctx, client, repo, query, seenURLs, seenNames)
			if err != nil {
				continue
			}
			if skipped {
				report.SkippedExisting++
				continue
			}
			if !found {
				continue
			}
			report.Candidates = append(report.Candidates, candidate)
			seenURLs[candidate.URL] = true
			seenNames[candidate.Name] = true
		}
	}

	sort.Slice(report.Candidates, func(i, j int) bool {
		if report.Candidates[i].ParsedNodes == report.Candidates[j].ParsedNodes {
			return report.Candidates[i].Repo < report.Candidates[j].Repo
		}
		return report.Candidates[i].ParsedNodes > report.Candidates[j].ParsedNodes
	})
	return report, nil
}

func WriteYAML(path string, report Report) error {
	data, err := yaml.Marshal(report)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func WriteMarkdown(path string, report Report) error {
	var b strings.Builder
	b.WriteString("# Discovered Public Sources\n\n")
	b.WriteString(fmt.Sprintf("- Generated at: `%s`\n", report.GeneratedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Searched repos: `%d`\n", report.SearchedRepos))
	b.WriteString(fmt.Sprintf("- Candidates: `%d`\n\n", len(report.Candidates)))
	b.WriteString("| Name | Format | Parsed nodes | Raw URL |\n")
	b.WriteString("| --- | --- | ---: | --- |\n")
	for _, c := range report.Candidates {
		b.WriteString(fmt.Sprintf("| `%s` | `%s` | %d | `%s` |\n", c.Name, c.Format, c.ParsedNodes, c.URL))
	}
	if len(report.Candidates) > 0 {
		b.WriteString("\n## Copy-ready entries\n\n```yaml\nsources:\n")
		for _, c := range report.Candidates {
			b.WriteString(fmt.Sprintf("  - name: %s\n    url: %s\n    format: %s\n    enabled: false\n", c.Name, c.URL, c.Format))
		}
		b.WriteString("```\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func ExistingNames(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	for _, src := range cfg.Sources {
		out[src.Name] = true
	}
	return out
}

func ExistingURLs(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	for _, src := range cfg.Sources {
		out[src.URL] = true
	}
	return out
}

func probeRepo(ctx context.Context, client *http.Client, repo repoItem, query string, seenURLs, seenNames map[string]bool) (Candidate, bool, bool, error) {
	skippedExisting := false
	for _, relPath := range commonPaths {
		rawURL := rawURL(repo.FullName, repo.DefaultBranch, relPath)
		if seenURLs[rawURL] {
			skippedExisting = true
			continue
		}

		body, err := fetchBody(ctx, client, rawURL)
		if err != nil {
			continue
		}
		format, parsed := detectFormat(body)
		if format == "" || parsed == 0 {
			continue
		}

		name := uniqueName(repo.FullName, relPath, seenNames)
		return Candidate{
			Name:        name,
			URL:         rawURL,
			Format:      format,
			Enabled:     false,
			Repo:        repo.FullName,
			Branch:      repo.DefaultBranch,
			Path:        relPath,
			Query:       query,
			ParsedNodes: parsed,
			PushedAt:    repo.PushedAt,
		}, true, false, nil
	}
	return Candidate{}, false, skippedExisting, nil
}

func searchRepos(ctx context.Context, client *http.Client, token, query string, perQuery int) ([]repoItem, error) {
	u := "https://api.github.com/search/repositories?q=" + url.QueryEscape(query) +
		"&sort=updated&order=desc&per_page=" + fmt.Sprintf("%d", perQuery)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "free-vpn-subscriptions-discover/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github search %q: http %d", query, resp.StatusCode)
	}
	var parsed repoSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	return parsed.Items, nil
}

func fetchBody(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "free-vpn-subscriptions-discover/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxProbeBytes))
}

func detectFormat(body []byte) (string, int) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", 0
	}

	if looksLikeClash(trimmed) {
		nodes, err := parse.Clash(body)
		if err == nil && len(nodes) > 0 {
			return "clash", len(nodes)
		}
	}

	if nodes, err := parse.Base64List(body); err == nil && len(nodes) > 0 {
		return "base64", len(nodes)
	}

	if nodes := parse.URIList(trimmed); len(nodes) > 0 {
		return "uri-list", len(nodes)
	}

	if nodes, err := parse.Clash(body); err == nil && len(nodes) > 0 {
		return "clash", len(nodes)
	}

	return "", 0
}

func looksLikeClash(body string) bool {
	return strings.Contains(body, "\nproxies:") ||
		strings.HasPrefix(body, "proxies:") ||
		(strings.Contains(body, "\nport:") && strings.Contains(body, "proxies:"))
}

func rawURL(repoFullName, branch, relPath string) string {
	return "https://raw.githubusercontent.com/" + repoFullName + "/" + branch + "/" + relPath
}

func uniqueName(repoFullName, relPath string, seen map[string]bool) string {
	base := strings.ToLower(strings.ReplaceAll(repoFullName, "/", "-"))
	filePart := strings.TrimSuffix(path.Base(relPath), path.Ext(relPath))
	name := sanitizeName(base + "-" + filePart)
	if !seen[name] {
		return name
	}
	for i := 2; ; i++ {
		next := fmt.Sprintf("%s-%d", name, i)
		if !seen[next] {
			return next
		}
	}
}

func sanitizeName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "source"
	}
	return out
}

func cloneSet(src map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range src {
		out[k] = v
	}
	return out
}
