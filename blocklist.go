package main

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

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

		// Parse blocklist entry as a network (single IPs become /32 for IPv4 or /128 for IPv6)
		var baseNet *net.IPNet
		if ip := net.ParseIP(address); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				baseNet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
			} else {
				baseNet = &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
			}
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
				if ip4 := ip.To4(); ip4 != nil {
					excludeNet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
				} else {
					excludeNet = &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
				}
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
