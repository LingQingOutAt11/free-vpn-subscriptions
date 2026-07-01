package discover

import "testing"

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantFormat string
	}{
		{
			name:       "uri list",
			body:       "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com#vl",
			wantFormat: "uri-list",
		},
		{
			name:       "base64",
			body:       "dmxlc3M6Ly8xMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP3NlY3VyaXR5PXRscyZzbmk9ZXhhbXBsZS5jb20jdmw=",
			wantFormat: "base64",
		},
		{
			name:       "clash",
			body:       "proxies:\n  - name: test\n    type: ss\n    server: 1.1.1.1\n    port: 8388\n    cipher: aes-128-gcm\n    password: pass\n",
			wantFormat: "clash",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, count := detectFormat([]byte(tc.body))
			if got != tc.wantFormat {
				t.Fatalf("detectFormat() = %q, want %q", got, tc.wantFormat)
			}
			if count == 0 {
				t.Fatal("detectFormat() returned zero nodes")
			}
		})
	}
}
