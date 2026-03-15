package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Security constants
const (
	// httpTimeout caps each remote blocklist download.
	httpTimeout = 30 * time.Second
	// maxResponseSize caps how much data we read from a single remote URL (50 MB).
	maxResponseSize = 50 * 1024 * 1024
	// dockerOpTimeout caps each individual Docker stop/start call.
	dockerOpTimeout = 60 * time.Second
)

// httpClient is a shared client with a hard timeout; the zero-value http.Client has no timeout.
var httpClient = &http.Client{Timeout: httpTimeout}

// validContainerName matches Docker container names: starts with alphanumeric, then allows
// alphanumeric, hyphens, underscores, and periods — no path separators or shell metacharacters.
var validContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// privateIPNets holds RFC-1918, loopback, link-local, and other reserved ranges used to
// block SSRF attacks that resolve to internal addresses.
var privateIPNets []*net.IPNet

func init() {
	reserved := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
		"100.64.0.0/10",  // carrier-grade NAT
		"0.0.0.0/8",
		"240.0.0.0/4", // reserved
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range reserved {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateIPNets = append(privateIPNets, ipNet)
		}
	}
}

// isPrivateIP returns true if ip falls within any reserved/private range.
func isPrivateIP(ip net.IP) bool {
	for _, ipNet := range privateIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// validateURLFunc is the URL validation function used by downloadFile.
// It is a package-level variable so unit tests can replace it with a no-op to
// reach mock HTTP servers without triggering the https-only / private-IP guards.
// Production code always uses the real validateURL implementation.
var validateURLFunc = validateURL

// validateURL enforces https-only and blocks SSRF via private/reserved IP resolution.
// Note: DNS rebinding between this check and the actual request is a known residual risk.
func validateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %q: %v", host, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil && isPrivateIP(ip) {
			return fmt.Errorf("URL %q resolves to reserved address %s", rawURL, addr)
		}
	}
	return nil
}

// validateConfFilePath ensures the output path is within the expected directory,
// preventing path-traversal writes to arbitrary filesystem locations.
// Both paths are cleaned before comparison so trailing slashes (e.g. macOS $TMPDIR)
// do not produce a double-separator that defeats the prefix check.
func validateConfFilePath(filePath string) error {
	if filePath == "" {
		return fmt.Errorf("nginx_conf_file_path is empty")
	}
	clean := filepath.Clean(filePath)
	allowedClean := filepath.Clean(allowedConfDir)
	prefix := allowedClean + string(filepath.Separator)
	if clean != allowedClean && !strings.HasPrefix(clean, prefix) {
		return fmt.Errorf("nginx_conf_file_path %q is outside allowed directory %q", filePath, allowedConfDir)
	}
	return nil
}

// validateContainerName rejects names containing shell metacharacters or path separators.
func validateContainerName(name string) error {
	if !validContainerName.MatchString(name) {
		return fmt.Errorf("container name %q contains invalid characters (allowed: [a-zA-Z0-9._-])", name)
	}
	return nil
}

// downloadFile fetches content from a specified URL.
// URLs must use https and must not resolve to private/reserved addresses (SSRF prevention).
// Downloads are bounded by httpTimeout and maxResponseSize.
func downloadFile(rawURL string) (string, error) {
	if err := validateURLFunc(rawURL); err != nil {
		return "", fmt.Errorf("URL validation failed: %v", err)
	}

	resp, err := httpClient.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error fetching URL %s: status code %d", rawURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", err
	}

	return string(body), nil
}
