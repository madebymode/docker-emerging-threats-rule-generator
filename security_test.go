package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDownloadRejectsUnsafeRedirects(t *testing.T) {
	original := validateURLFunc
	t.Cleanup(func() { validateURLFunc = original })
	for _, target := range []string{"http://example.com/list", "https://127.0.0.1/list", "https://169.254.169.254/latest/meta-data", "https://[::1]/list"} {
		t.Run(target, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusFound)
			}))
			defer server.Close()
			validateURLFunc = func(raw string) error {
				if raw == server.URL {
					return nil
				}
				return validateURL(raw)
			}
			if content, err := downloadFile(server.URL); err == nil || content != "" {
				t.Fatalf("unsafe redirect accepted: content=%q err=%v", content, err)
			}
		})
	}
}

func TestDownloadAllowsValidatedRedirect(t *testing.T) {
	original := validateURLFunc
	t.Cleanup(func() { validateURLFunc = original })
	var validated []string
	validateURLFunc = func(raw string) error { validated = append(validated, raw); return nil }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/list", http.StatusFound)
			return
		}
		io.WriteString(w, "1.2.3.4\n")
	}))
	defer server.Close()
	content, err := downloadFile(server.URL)
	if err != nil || content != "1.2.3.4\n" || len(validated) != 2 {
		t.Fatalf("valid redirect failed: %q %v validations=%v", content, err, validated)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type repeatingReader struct{}

func (repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '1'
	}
	return len(p), nil
}

func TestDownloadRejectsOversizedResponse(t *testing.T) {
	original := downloadClient.Transport
	t.Cleanup(func() { downloadClient.Transport = original })
	downloadClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(io.LimitReader(repeatingReader{}, maxResponseSize+1))}, nil
	})
	content, err := downloadFile("https://example.com/list")
	if err == nil || content != "" || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response was not rejected: length=%d err=%v", len(content), err)
	}
}

func TestReservedDownloadAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "127.0.0.1", "10.1.2.3", "169.254.169.254", "224.0.0.1", "255.255.255.255", "::", "::1", "ff02::1", "::ffff:127.0.0.1"} {
		if !isPrivateIP(net.ParseIP(address)) {
			t.Errorf("reserved address allowed: %s", address)
		}
	}
	if isPrivateIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("public IP rejected")
	}
}

func TestOutputCannotEscapeViaSymlink(t *testing.T) {
	original := allowedConfDir
	allowedConfDir = t.TempDir()
	t.Cleanup(func() { allowedConfDir = original })
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(allowedConfDir, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := writeBlocklistFile(nil, nil, filepath.Join(allowedConfDir, "escape", "blocklist.conf")); err == nil {
		t.Fatal("write through escaping symlink succeeded")
	}
	files, err := os.ReadDir(outside)
	if err != nil || len(files) != 0 {
		t.Fatalf("outside directory modified: %v %v", files, err)
	}
}

func TestOutputReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	original := allowedConfDir
	allowedConfDir = t.TempDir()
	t.Cleanup(func() { allowedConfDir = original })
	outside := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(allowedConfDir, "blocklist.conf")
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}
	if err := writeBlocklistFile(nil, map[string][]string{"1.2.3.4": {"local_blocklist"}}, target); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("symlink target changed: %q %v", content, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("nginx cannot read generated file: %v", info.Mode())
	}
}

func TestLabelsCannotInjectNginxDirectives(t *testing.T) {
	safe := regexp.MustCompile(`^[a-zA-Z0-9._+-]+$`)
	for _, source := range []string{"https://example.com/a%3B%0A%7D%0Ainclude%20evil.conf", "https://example.com/%22%24host.txt", "local; } include evil; #", "https://example.com/0.txt", ""} {
		label := labelFromSource(source)
		if !safe.MatchString(label) || label == "0" {
			t.Errorf("unsafe or falsy label %q from %q", label, source)
		}
	}
	for source, want := range map[string]string{"local_blocklist": "local", "https://www.ipdeny.com/cn-aggregated.zone": "cn", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt": "ipsum-8"} {
		if got := labelFromSource(source); got != want {
			t.Errorf("label changed: %s got=%s want=%s", source, got, want)
		}
	}
}
