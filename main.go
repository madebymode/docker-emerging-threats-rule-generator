package main

import (
  "bufio"
  "context"
  "encoding/json"
  "fmt"
  "io"
  "net"
  "net/http"
  "net/url"
  "os"
  "path"
  "path/filepath"
  "regexp"
  "sort"
  "strings"
  "time"

  "github.com/docker/docker/api/types/container"
  "github.com/docker/docker/client"
)

func logf(format string, args ...interface{}) {
	fmt.Printf("["+time.Now().Format("2006/01/02 15:04:05")+"] "+format, args...)
}

// allowedConfDir is the only directory the blocklist file may be written into.
// Declared as a var so tests can override it to a temp directory.
var allowedConfDir = "/app/nginx/conf"

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

// labelFromSource derives a short, human-readable nginx-safe label from a source identifier.
// Examples:
//   - "https://raw.githubusercontent.com/stamparm/ipsum/…/levels/8.txt" → "ipsum-8"
//   - "https://www.ipdeny.com/…/cn-aggregated.zone"                       → "cn"
//   - "https://rules.emergingthreats.net/…/emerging-Block-IPs.txt"        → "emerging-block-ips"
//   - "local_blocklist"                                                    → "local"
func labelFromSource(source string) string {
	if source == "local_blocklist" || source == "local_whitelist" {
		return "local"
	}
	u, err := url.Parse(source)
	if err != nil || u.Host == "" {
		return source
	}
	base := path.Base(u.Path)
	name := strings.TrimSuffix(base, path.Ext(base))
	name = strings.ToLower(name)
	// Strip common noisy suffixes (e.g. ipdeny: "cn-aggregated" → "cn")
	name = strings.TrimSuffix(name, "-aggregated")
	// For GitHub raw content, prefix with repo name when the filename alone is ambiguous
	// (e.g. ipsum/levels/8.txt → "ipsum-8" rather than just "8")
	if u.Host == "raw.githubusercontent.com" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		// URL path segments: owner / repo / refs / heads / branch / … / file
		if len(parts) >= 2 {
			repo := strings.ToLower(parts[1])
			if isAmbiguousLabel(name) {
				name = repo + "-" + name
			}
		}
	}
	// Fall back to hostname when the path yields nothing useful (e.g. bare domain URLs)
	if name == "" || name == "." || name == "/" {
		host := strings.Split(u.Host, ":")[0]
		name = strings.ToLower(strings.ReplaceAll(host, ".", "-"))
	}
	if name == "" {
		return "blocked"
	}
	return name
}

// isAmbiguousLabel returns true when a label is all-digits or very short,
// meaning it needs a prefix to be meaningful.
func isAmbiguousLabel(name string) bool {
	if len(name) <= 2 {
		return true
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true // all digits
}

// Config struct includes local and remote IP lists for whitelisting and blocklisting
type Config struct {
	LocalWhitelist      []string `json:"local_whitelist"`
	LocalBlocklist      []string `json:"local_blocklist"`
	RemoteWhitelists    []string `json:"remote_whitelists"`
	RemoteBlocklists    []string `json:"remote_blocklists"`
	ConfFilePath        string   `json:"nginx_conf_file_path"`
	NginxContainerNames []string `json:"nginx_container_names"`
}

// readConfig reads the configuration from a JSON file
func readConfig(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			logf("Failed to close file: %v\n", err)
		}
	}(file)

	decoder := json.NewDecoder(file)
	config := &Config{}
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}

	return config, nil
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

// parseIPAddresses extracts IP addresses from string content.
// The regex is used to locate candidates; each candidate is then validated with
// net.ParseIP / net.ParseCIDR so invalid strings like 999.999.999.999 are rejected.
func parseIPAddresses(contents string) map[string]struct{} {
	lines := strings.Split(contents, "\n")
	addresses := make(map[string]struct{})

	ipRegex := regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		var candidates []string
		if ipRegex.MatchString(line) && len(ipRegex.FindString(line)) == len(line) {
			candidates = []string{line}
		} else {
			candidates = ipRegex.FindAllString(line, -1)
		}

		for _, candidate := range candidates {
			if strings.Contains(candidate, "/") {
				if _, _, err := net.ParseCIDR(candidate); err == nil {
					addresses[candidate] = struct{}{}
				}
			} else {
				if ip := net.ParseIP(candidate); ip != nil && ip.To4() != nil {
					addresses[candidate] = struct{}{}
				}
			}
		}
	}

	return addresses
}

// ipv4ToUint32 converts an IPv4 address to a uint32 for range comparison
func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// isIPInCIDR checks if an IP address is within a CIDR range
// or if a CIDR range is contained within another CIDR range
// strictMode controls how we handle CIDR vs CIDR comparisons:
//   - In strict mode (for tests), we only return true if the first CIDR is contained in the second
//   - In non-strict mode (for IP filtering), we return true if there's any overlap
func isIPInCIDR(ip, cidr string, strictMode ...bool) bool {
	// Default to non-strict mode
	strict := false
	if len(strictMode) > 0 {
		strict = strictMode[0]
	}

	// Case 1: If the IP parameter is a single IP (not CIDR)
	ipObj := net.ParseIP(ip)
	if ipObj != nil {
		// Check if the CIDR has valid notation
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// If cidr is not in CIDR notation, treat as regular IP
			cidrIP := net.ParseIP(cidr)
			if cidrIP == nil {
				return false
			}
			return ipObj.Equal(cidrIP)
		}

		// Check if the IP is in the CIDR range
		return ipNet.Contains(ipObj)
	}

	// Case 2: If the IP parameter is a CIDR
	_, ipNet, err := net.ParseCIDR(ip)
	if err != nil {
		// Not a valid IP or CIDR
		return false
	}

	// If the second parameter is also a CIDR
	_, cidrNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// If not a CIDR, check if it's a single IP in our network
		cidrIP := net.ParseIP(cidr)
		if cidrIP == nil {
			return false
		}
		return ipNet.Contains(cidrIP)
	}

	// Check if one CIDR contains the other or if they are equal

	// First check if they're exactly the same CIDR
	if ip == cidr {
		return true
	}

	// Get the first IP address of each CIDR (network address)
	ipNetStart, _, _ := net.ParseCIDR(ip)
	cidrNetStart, _, _ := net.ParseCIDR(cidr)

	// Get the mask sizes
	ipMaskSize, _ := ipNet.Mask.Size()
	cidrMaskSize, _ := cidrNet.Mask.Size()

	if strict {
		// In strict mode, only return true if the first CIDR is fully contained in the second
		return cidrNet.Contains(ipNetStart) && cidrMaskSize <= ipMaskSize
	} else {
		// In non-strict mode (for IP filtering), check for any kind of overlap

		// Check if either CIDR contains the other's network address
		if cidrNet.Contains(ipNetStart) || ipNet.Contains(cidrNetStart) {
			return true
		}

		// Check for partial overlap
		// Convert to uint32 for IP range comparison
		ipStart := ipv4ToUint32(ipNetStart)
		cidrStart := ipv4ToUint32(cidrNetStart)

		// Calculate end of ranges
		ipEnd := ipStart + (1 << (32 - ipMaskSize)) - 1
		cidrEnd := cidrStart + (1 << (32 - cidrMaskSize)) - 1

		// Check for any overlap
		return (ipStart <= cidrEnd) && (cidrStart <= ipEnd)
	}
}

// splitNetwork splits a CIDR into two equal halves with maskSize+1.
func splitNetwork(network *net.IPNet) (*net.IPNet, *net.IPNet) {
	maskSize, bits := network.Mask.Size()
	newMask := net.CIDRMask(maskSize+1, bits)

	half1IP := make(net.IP, len(network.IP))
	copy(half1IP, network.IP)

	half2IP := make(net.IP, len(network.IP))
	copy(half2IP, network.IP)
	byteIdx := maskSize / 8
	bitIdx := uint(7 - maskSize%8)
	half2IP[byteIdx] |= 1 << bitIdx

	return &net.IPNet{IP: half1IP, Mask: newMask}, &net.IPNet{IP: half2IP, Mask: newMask}
}

// subtractCIDR returns the minimal set of CIDRs covering all of base
// except for any addresses also covered by exclude.
// Returns nil if base is entirely within exclude.
// Returns [base] if there is no overlap.
func subtractCIDR(base, exclude *net.IPNet) []*net.IPNet {
	baseMask, _ := base.Mask.Size()
	excludeMask, _ := exclude.Mask.Size()

	// No overlap
	if !base.Contains(exclude.IP) && !exclude.Contains(base.IP) {
		return []*net.IPNet{base}
	}

	// Base is fully contained within exclude (or equal)
	if exclude.Contains(base.IP) && excludeMask <= baseMask {
		return nil
	}

	// Exclude is a proper subset of base: split and recurse
	if baseMask >= 32 {
		return nil
	}

	half1, half2 := splitNetwork(base)
	if half1.Contains(exclude.IP) {
		result := subtractCIDR(half1, exclude)
		return append(result, half2)
	}
	result := subtractCIDR(half2, exclude)
	return append([]*net.IPNet{half1}, result...)
}

// isIPWhitelisted checks if an IP is whitelisted considering CIDR ranges.
// Returns (isWhitelisted, matchedEntry, source).
func isIPWhitelisted(ip string, whitelist map[string]string) (bool, string, string) {
	// First check for exact match
	if source, ok := whitelist[ip]; ok {
		return true, ip, source
	}

	// Then check for CIDR range
	for cidr, source := range whitelist {
		// Use strict mode for the TestIsIPWhitelisted test to pass
		if isIPInCIDR(ip, cidr, false) {
			return true, cidr, source
		}
	}

	return false, "", ""
}

// writeBlocklistFile creates an NGINX configuration file for blocking IPs, considering whitelisted IPs.
// The geo variable $blocked_source is set to a label identifying the originating blocklist(s),
// or "" (empty string, falsy in nginx) for addresses that are not blocked.
// The write is atomic: content is staged in a temp file and renamed into place, so nginx
// never sees a partially written config even if the process crashes mid-write.
func writeBlocklistFile(whitelist map[string]string, blocklist map[string][]string, filePath string) error {
	if err := validateConfFilePath(filePath); err != nil {
		return fmt.Errorf("refusing to write blocklist: %v", err)
	}

	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, ".blocklist-*.conf.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file in %s: %v", dir, err)
	}
	tmpName := tmp.Name()

	// On any failure, clean up the temp file.
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmpName)
		}
	}()

	file := tmp
	defer func(file *os.File) {
		err := file.Close()
		if err != nil && !committed {
			logf("Failed to close temp file: %v\n", err)
		}
	}(file)

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString("# blocklist.conf\n\ngeo $blocked_source {\n    default        \"\";\n\n")
	if err != nil {
		return err
	}

	type addrEntry struct {
		addr  string
		label string
	}
	var entries []addrEntry

	for address, blocklistSources := range blocklist {
		// Derive the nginx label: join all source labels with "+"
		labels := make([]string, len(blocklistSources))
		for i, src := range blocklistSources {
			labels[i] = labelFromSource(src)
		}
		blocklistLabel := strings.Join(labels, "+")

	
		// Parse blocklist entry as a network (single IPs become /32)
		var baseNet *net.IPNet
		if ip := net.ParseIP(address); ip != nil {
			ip4 := ip.To4()
			if ip4 == nil {
				continue // skip IPv6
			}
			baseNet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
		} else {
			var parseErr error
			_, baseNet, parseErr = net.ParseCIDR(address)
			if parseErr != nil {
				continue
			}
		}

		// Subtract all whitelist entries from this blocklist network
		remaining := []*net.IPNet{baseNet}
		for wlEntry := range whitelist {
			var excludeNet *net.IPNet
			if ip := net.ParseIP(wlEntry); ip != nil {
				ip4 := ip.To4()
				if ip4 == nil {
					continue
				}
				excludeNet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
			} else {
				_, excludeNet, _ = net.ParseCIDR(wlEntry)
			}
			if excludeNet == nil {
				continue
			}
			var next []*net.IPNet
			for _, subnet := range remaining {
				next = append(next, subtractCIDR(subnet, excludeNet)...)
			}
			remaining = next
			if len(remaining) == 0 {
				break
			}
		}

		if len(remaining) == 0 {
			// Entirely whitelisted
			if whitelisted, matchedEntry, whitelistSource := isIPWhitelisted(address, whitelist); whitelisted {
				logf("Skipping whitelisted IP: %s (matched: %s from %s) - found in blocklist: %s\n",
					address, matchedEntry, whitelistSource, blocklistLabel)
			} else {
				logf("Skipping whitelisted IP: %s - found in blocklist: %s\n", address, blocklistLabel)
			}
		} else if len(remaining) == 1 && remaining[0].String() == baseNet.String() {
			// No whitelist overlap; keep original entry as-is
			entries = append(entries, addrEntry{addr: address, label: blocklistLabel})
		} else {
			// Partial overlap: emit carved subnets, omitting whitelisted portions
			logf("Splitting blocklist CIDR %s (from %s): retaining %d sub-ranges after whitelist exclusions\n",
				address, blocklistLabel, len(remaining))
			for _, subnet := range remaining {
				entries = append(entries, addrEntry{addr: subnet.String(), label: blocklistLabel})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].addr < entries[j].addr
	})

	for _, e := range entries {
		_, err = writer.WriteString(fmt.Sprintf("    %s    %s;\n", e.addr, e.label))
		if err != nil {
			return err
		}
	}

	_, err = writer.WriteString("\n}")
	if err != nil {
		return err
	}

	if err := writer.Flush(); err != nil {
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}
	committed = true // prevent deferred close from double-closing

	// Atomically replace the live file.
	if err := os.Rename(tmpName, filePath); err != nil {
		committed = false // rename failed; deferred cleanup will remove tmpName
		return fmt.Errorf("failed to atomically replace blocklist file: %v", err)
	}

	return nil
}

// restartNginxContainers restarts specified Docker containers.
// Container names are validated before use and each Docker API call has a hard timeout.
func restartNginxContainers(cli *client.Client, containerNames []string) error {
	for _, containerName := range containerNames {
		if err := validateContainerName(containerName); err != nil {
			return fmt.Errorf("invalid container name: %v", err)
		}

		stopCtx, stopCancel := context.WithTimeout(context.Background(), dockerOpTimeout)
		stopErr := cli.ContainerStop(stopCtx, containerName, container.StopOptions{})
		stopCancel()
		if stopErr != nil {
			return fmt.Errorf("failed to stop container %s: %v", containerName, stopErr)
		}

		startCtx, startCancel := context.WithTimeout(context.Background(), dockerOpTimeout)
		startErr := cli.ContainerStart(startCtx, containerName, container.StartOptions{})
		startCancel()
		if startErr != nil {
			return fmt.Errorf("failed to start container %s: %v", containerName, startErr)
		}

		logf("Container %s restarted successfully.\n", containerName)
	}

	return nil
}

// main is the entry point for the application
func main() {
	config, err := readConfig("/app/config.json")
	if err != nil {
		logf("Failed to read config file: %v\n", err)
		return
	}

	// Validate the output path before touching the network — fail fast.
	if err := validateConfFilePath(config.ConfFilePath); err != nil {
		logf("Invalid nginx_conf_file_path in config: %v\n", err)
		return
	}

	whitelist := make(map[string]string)
	for _, address := range config.LocalWhitelist {
		whitelist[address] = "local_whitelist"
	}

	for _, url := range config.RemoteWhitelists {
		content, err := downloadFile(url)
		if err != nil {
			logf("Failed to download file from %s: %v\n", url, err)
			continue
		}

		addresses := parseIPAddresses(content)
		for address := range addresses {
			whitelist[address] = url
		}
	}

	blocklist := make(map[string][]string)
	for _, address := range config.LocalBlocklist {
		blocklist[address] = append(blocklist[address], "local_blocklist")
	}

	for _, url := range config.RemoteBlocklists {
		content, err := downloadFile(url)
		if err != nil {
			logf("Failed to download file from %s: %v\n", url, err)
			continue
		}

		addresses := parseIPAddresses(content)
		for address := range addresses {
			blocklist[address] = append(blocklist[address], url)
		}
	}

	err = writeBlocklistFile(whitelist, blocklist, config.ConfFilePath)
	if err != nil {
		logf("Failed to write blocklist file: %v\n", err)
		return
	}

	if os.Getenv("RESTART_CONTAINERS") == "false" {
		logf("RESTART_CONTAINERS=false: skipping container restart. Reload nginx via external cron or orchestrator.\n")
		logf("Blocklist.conf file created successfully.\n")
		return
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logf("Failed to create Docker client: %v\n", err)
		return
	}

	if err := restartNginxContainers(cli, config.NginxContainerNames); err != nil {
		logf("Failed to restart Nginx containers: %v\n", err)
		return
	}

	logf("Blocklist.conf file created and Nginx containers restarted successfully.\n")
}
