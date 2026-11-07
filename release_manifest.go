//go:build native

package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
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

// Both checking and installation authenticate metadata against embedded keys.
func fetchReleaseManifest(target string, keys []ed25519.PublicKey) (*releaseManifest, error) {
	base := "https://github.com/" + updateRepo + "/releases/download/" + target + "/"
	data, err := downloadFile(base + "manifest.json")
	if err != nil {
		return nil, err
	}
	sig, err := downloadFile(base + "manifest.json.sig")
	if err != nil {
		return nil, err
	}
	return verifyManifest([]byte(data), []byte(sig), keys, target)
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
