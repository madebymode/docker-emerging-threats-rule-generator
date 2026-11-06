//go:build native

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const updateRepo = "madebymode/docker-emerging-threats-rule-generator"

// Only explicit v3.MINOR.PATCH tags are eligible. The timestamped builds
// published from every master push are never installed automatically.
var releaseTagPattern = regexp.MustCompile(`^v3\.(\d+)\.(\d+)$`)

// releaseManifest is signed in CI. Signing the manifest instead of each binary
// binds the tag, the publish time and every asset digest together, so a valid
// signature cannot be replayed onto another tag or architecture.
type releaseManifest struct {
	Tag     string            `json:"tag"`
	Created time.Time         `json:"created"`
	Assets  map[string]string `json:"assets"` // asset name -> sha256 hex
}

type githubRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// Indirection so tests can exercise installation without systemd.
var restartService = func(name string) error {
	out, err := exec.Command("systemctl", "restart", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %v\n%s", name, err, out)
	}
	return nil
}

var serviceHealthy = func(name string) bool {
	time.Sleep(10 * time.Second)
	return exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil
}

// selfUpdate installs the newest eligible signed release over the running
// binary. Settings come from the environment (see native-install.md):
// ETR_AUTO_UPDATE, ETR_UPDATE_PIN, ETR_UPDATE_DELAY_HOURS, ETR_SERVICE.
func selfUpdate() error {
	if os.Getenv("ETR_AUTO_UPDATE") == "false" {
		logf("ETR_AUTO_UPDATE=false: self-update disabled\n")
		return nil
	}
	keys, err := parseReleaseKeys(releaseSigningKeysPEM)
	if err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}

	pin := os.Getenv("ETR_UPDATE_PIN")
	target := pin
	if pin != "" {
		if !releaseTagPattern.MatchString(pin) {
			return fmt.Errorf("ETR_UPDATE_PIN=%q is not a v3.MINOR.PATCH tag", pin)
		}
	} else {
		body, err := downloadFile("https://api.github.com/repos/" + updateRepo + "/releases?per_page=50")
		if err != nil {
			return fmt.Errorf("listing releases: %v", err)
		}
		var releases []githubRelease
		if err := json.Unmarshal([]byte(body), &releases); err != nil {
			return fmt.Errorf("parsing release list: %v", err)
		}
		if target = newestRelease(releases); target == "" {
			logf("No signed v3.x.y release published yet; running %s\n", version)
			return nil
		}
	}

	if !shouldInstall(version, target, pin != "") {
		logf("Up to date: running %s, newest eligible release is %s\n", version, target)
		return nil
	}

	base := "https://github.com/" + updateRepo + "/releases/download/" + target + "/"
	manifestData, err := downloadFile(base + "manifest.json")
	if err != nil {
		return err
	}
	sig, err := downloadFile(base + "manifest.json.sig")
	if err != nil {
		return err
	}
	manifest, err := verifyManifest([]byte(manifestData), []byte(sig), keys, target)
	if err != nil {
		return err
	}
	logf("Signature verified for %s manifest (published %s)\n", target, manifest.Created.Format(time.RFC3339))

	// A pin is an explicit operator choice, so it skips the waiting period.
	delay := time.Duration(envInt("ETR_UPDATE_DELAY_HOURS", 72, 0, 720)) * time.Hour
	if pin == "" {
		if ready := manifest.Created.Add(delay); time.Now().Before(ready) {
			logf("%s is newer than the %s waiting period; installing after %s\n",
				target, delay, ready.Format(time.RFC3339))
			return nil
		}
	}

	asset := "etr-linux-" + runtime.GOARCH
	want, ok := manifest.Assets[asset]
	if !ok {
		return fmt.Errorf("manifest for %s has no %s asset", target, asset)
	}
	binary, err := downloadFile(base + asset)
	if err != nil {
		return err
	}
	return installBinary(exe, []byte(binary), want, target, os.Getenv("ETR_SERVICE"))
}

func parseReleaseKeys(data []byte) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for rest := data; len(strings.TrimSpace(string(rest))) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("release signing key is not valid PEM")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing release signing key: %v", err)
		}
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("release signing key is %T, want Ed25519", pub)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no release signing keys are compiled into this binary")
	}
	return keys, nil
}

func verifyManifest(data, sig []byte, keys []ed25519.PublicKey, tag string) (*releaseManifest, error) {
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("manifest signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	verified := false
	for _, key := range keys {
		if ed25519.Verify(key, data, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("manifest signature does not match any trusted release key")
	}
	var m releaseManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing signed manifest: %v", err)
	}
	if m.Tag != tag {
		return nil, fmt.Errorf("signed manifest is for %q, not %q", m.Tag, tag)
	}
	if m.Created.IsZero() {
		return nil, fmt.Errorf("signed manifest has no created time")
	}
	return &m, nil
}

// parseTag returns the minor and patch numbers of a v3.MINOR.PATCH tag.
func parseTag(tag string) (minor, patch int, ok bool) {
	m := releaseTagPattern.FindStringSubmatch(tag)
	if m == nil {
		return 0, 0, false
	}
	minor, err1 := strconv.Atoi(m[1])
	patch, err2 := strconv.Atoi(m[2])
	return minor, patch, err1 == nil && err2 == nil
}

func tagLess(a, b string) bool {
	am, ap, _ := parseTag(a)
	bm, bp, _ := parseTag(b)
	return am < bm || (am == bm && ap < bp)
}

func newestRelease(releases []githubRelease) string {
	newest := ""
	for _, r := range releases {
		if r.Draft || r.Prerelease {
			continue
		}
		if _, _, ok := parseTag(r.TagName); !ok {
			continue
		}
		if newest == "" || tagLess(newest, r.TagName) {
			newest = r.TagName
		}
	}
	return newest
}

// shouldInstall never moves to an older release unless the operator pinned
// it. A development or timestamped build counts as older than any release.
func shouldInstall(current, target string, pinned bool) bool {
	if pinned {
		return current != target
	}
	if _, _, ok := parseTag(current); !ok {
		return true
	}
	return tagLess(current, target)
}

// installBinary atomically replaces exe, keeping the previous binary as
// exe.prev, and rolls back if the service does not come back up.
func installBinary(exe string, binary []byte, wantSHA256, tag, service string) error {
	sum := sha256.Sum256(binary)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, wantSHA256) {
		return fmt.Errorf("downloaded binary sha256 %s does not match signed manifest %s", got, wantSHA256)
	}

	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".etr-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0755); err != nil {
		return err
	}

	// Confirms the binary runs on this host and reports the expected tag.
	out, err := exec.Command(tmp.Name(), "--version").Output()
	if err != nil {
		return fmt.Errorf("new binary failed to run: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != tag {
		return fmt.Errorf("new binary reports version %q, want %q", got, tag)
	}

	prev := exe + ".prev"
	current, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if err := os.WriteFile(prev, current, 0755); err != nil {
		return fmt.Errorf("saving previous binary: %v", err)
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		return fmt.Errorf("replacing binary: %v", err)
	}
	logf("Installed %s over %s (previous binary kept at %s)\n", tag, version, prev)

	if service == "" {
		service = "etr"
	}
	if service == "none" {
		return nil
	}
	if err := restartService(service); err == nil && serviceHealthy(service) {
		logf("%s restarted on %s\n", service, tag)
		return nil
	}

	logf("%s did not come back up on %s; rolling back to %s\n", service, tag, version)
	if err := os.Rename(prev, exe); err != nil {
		return fmt.Errorf("rollback failed, restore %s manually: %v", prev, err)
	}
	if err := restartService(service); err != nil {
		return fmt.Errorf("rolled back, but restart failed: %v", err)
	}
	return fmt.Errorf("update to %s rolled back: %s failed to start", tag, service)
}
