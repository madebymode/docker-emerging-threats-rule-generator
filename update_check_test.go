//go:build native

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type releaseTestNotifier struct {
	name  string
	calls int
	fail  bool
	body  string
}

func (n *releaseTestNotifier) Name() string { return n.name }
func (n *releaseTestNotifier) Send(_, body string) error {
	n.calls++
	n.body = body
	if n.fail {
		return errors.New("test delivery failure")
	}
	return nil
}

// A strict transport makes any executable download an immediate test failure.
func releaseCheckFixture(t *testing.T) ([]ed25519.PublicKey, *[]string, *bool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(releaseManifest{Tag: "v3.2.0", Created: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Assets: map[string]string{"etr-linux-arm64": "unused"}})
	sig := ed25519.Sign(private, manifest)
	invalid := false
	var requests []string
	oldTransport, oldValidator, oldVersion := downloadClient.Transport, validateURLFunc, version
	t.Cleanup(func() { downloadClient.Transport, validateURLFunc, version = oldTransport, oldValidator, oldVersion })
	version = "v3.1.0"
	validateURLFunc = func(string) error { return nil }
	downloadClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.String())
		var data string
		switch req.URL.String() {
		case "https://api.github.com/repos/" + updateRepo + "/releases?per_page=50":
			data = `[{"tag_name":"v3.2.0"},{"tag_name":"v3.9.0","prerelease":true},{"tag_name":"v3-2026-11-01"}]`
		case "https://github.com/" + updateRepo + "/releases/download/v3.2.0/manifest.json":
			data = string(manifest)
		case "https://github.com/" + updateRepo + "/releases/download/v3.2.0/manifest.json.sig":
			data = string(sig)
			if invalid {
				data = strings.Repeat("x", ed25519.SignatureSize)
			}
		default:
			t.Errorf("unexpected request (checks must not download binaries): %s", req.URL)
			return nil, errors.New("unexpected request")
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(data))}, nil
	})
	return []ed25519.PublicKey{public}, &requests, &invalid
}

func TestReleaseCheckOnlyFetchesAuthenticatedMetadata(t *testing.T) {
	keys, requests, invalid := releaseCheckFixture(t)
	n := &releaseTestNotifier{name: "webhook"}
	dir := t.TempDir()
	now := time.Now()
	*invalid = true
	if err := checkRelease(keys, []Notifier{n}, dir, now, time.Hour); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if n.calls != 0 {
		t.Fatal("unverified release was announced")
	}
	if files, _ := os.ReadDir(dir); len(files) != 0 {
		t.Fatal("unverified metadata changed state")
	}
	*invalid = false
	*requests = nil
	if err := checkRelease(keys, []Notifier{n}, dir, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 3 || n.calls != 1 {
		t.Fatalf("requests=%v notifications=%d", *requests, n.calls)
	}
	for _, want := range []string{"installed=v3.1.0", "available=v3.2.0", "published=", "/releases/tag/v3.2.0"} {
		if !strings.Contains(n.body, want) {
			t.Errorf("notice missing %s", want)
		}
	}
	info, err := os.Stat(filepath.Join(dir, noticeFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("notification state permissions: %v %v", info, err)
	}
}

func TestReleaseNoticesDeduplicateRemindAndRetryPerChannel(t *testing.T) {
	keys, _, _ := releaseCheckFixture(t)
	a := &releaseTestNotifier{name: "a"}
	b := &releaseTestNotifier{name: "b", fail: true}
	notifiers := []Notifier{a, b}
	dir, now := t.TempDir(), time.Now()
	if err := checkRelease(keys, notifiers, dir, now, 7*24*time.Hour); err == nil {
		t.Fatal("delivery failure not reported")
	}
	b.fail = false
	if err := checkRelease(keys, notifiers, dir, now.Add(time.Hour), 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if a.calls != 1 || b.calls != 2 {
		t.Fatalf("successful channel resent or failed channel not retried: %d %d", a.calls, b.calls)
	}
	if err := checkRelease(keys, notifiers, dir, now.Add(8*24*time.Hour), 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if a.calls != 2 || b.calls != 3 {
		t.Fatal("weekly reminder not sent")
	}
	version = "v3.1.1"
	if err := checkRelease(keys, notifiers, dir, now.Add(8*24*time.Hour+time.Hour), 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if a.calls != 3 || b.calls != 4 {
		t.Fatal("installed version change did not reset deduplication")
	}
	version = "v3.2.0"
	if err := checkRelease(keys, notifiers, dir, now.Add(20*24*time.Hour), time.Hour); err != nil {
		t.Fatal(err)
	}
	if a.calls != 3 || b.calls != 4 {
		t.Fatal("current version generated an update alert")
	}
}

func TestReleaseCheckLoggingNeedsNoWritableState(t *testing.T) {
	keys, _, _ := releaseCheckFixture(t)
	if err := checkRelease(keys, nil, filepath.Join(t.TempDir(), "missing"), time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseCheckNetworkFailureDoesNotNotify(t *testing.T) {
	keys, _, _ := releaseCheckFixture(t)
	downloadClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})
	n := &releaseTestNotifier{name: "webhook"}
	if err := checkRelease(keys, []Notifier{n}, t.TempDir(), time.Now(), time.Hour); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("failed check reported as success: %v", err)
	}
	if n.calls != 0 {
		t.Fatal("failed check sent an availability notice")
	}
}

func TestSelfUpdateOptInReachesReleaseDiscovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is rejected before policy evaluation")
	}
	_, _, _ = releaseCheckFixture(t)
	t.Setenv("ETR_AUTO_UPDATE", "true")
	t.Setenv("ETR_UPDATE_PIN", "")
	calls := 0
	downloadClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Host != "api.github.com" {
			t.Fatalf("unexpected request: %s", req.URL)
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader("[]"))}, nil
	})
	if err := selfUpdate(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("explicit opt-in did not check releases")
	}
}

func TestReleaseCheckRefusesEscapingStateSymlink(t *testing.T) {
	keys, _, _ := releaseCheckFixture(t)
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, noticeFile)); err != nil {
		t.Fatal(err)
	}
	n := &releaseTestNotifier{name: "webhook"}
	if err := checkRelease(keys, []Notifier{n}, dir, time.Now(), time.Hour); err == nil {
		t.Fatal("escaping symlink allowed")
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "keep" || n.calls != 0 {
		t.Fatal("unsafe state was used")
	}
}

func TestSelfUpdateRequiresExplicitOptIn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is rejected before policy evaluation")
	}
	_, requests, _ := releaseCheckFixture(t)
	for _, value := range []string{"", "false", "TRUE", "typo"} {
		t.Setenv("ETR_AUTO_UPDATE", value)
		if err := selfUpdate(); err != nil {
			t.Fatal(err)
		}
	}
	if len(*requests) != 0 {
		t.Fatal("disabled updater reached the network")
	}
}

func TestReleaseCheckRefusesRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if err := checkForUpdates(); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Fatalf("root check not rejected: %v", err)
	}
}
