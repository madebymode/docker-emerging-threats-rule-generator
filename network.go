package main

import (
	"net"
	"regexp"
	"strings"
)

// parseIPAddresses extracts IP addresses from string content.
// The regex is used to locate IPv4 candidates; each candidate is then validated with
// net.ParseIP / net.ParseCIDR so invalid strings like 999.999.999.999 are rejected.
// IPv6 addresses are detected by scanning for colon-containing tokens on each line.
func parseIPAddresses(contents string) map[string]struct{} {
	lines := strings.Split(contents, "\n")
	addresses := make(map[string]struct{})

	ipRegex := regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// IPv4 pass
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

		// IPv6 pass – any colon-containing token that parses cleanly
		for _, token := range strings.Fields(line) {
			if !strings.Contains(token, ":") {
				continue
			}
			token = strings.TrimSuffix(token, ",") // strip trailing punctuation
			if strings.Contains(token, "/") {
				if ip6, ipNet, err := net.ParseCIDR(token); err == nil && ip6.To4() == nil {
					addresses[ipNet.String()] = struct{}{}
				}
			} else {
				if ip := net.ParseIP(token); ip != nil && ip.To4() == nil {
					addresses[ip.String()] = struct{}{}
				}
			}
		}
	}

	return addresses
}

// isIPInCIDR checks if an IP address is within a CIDR range
// or if a CIDR range is contained within another CIDR range.
// strictMode controls how CIDR vs CIDR comparisons work:
//   - strict mode: true only if the first CIDR is fully contained in the second
//   - non-strict mode: true if there is any overlap (one network address is inside the other)
func isIPInCIDR(ip, cidr string, strictMode ...bool) bool {
	// Default to non-strict mode
	strict := false
	if len(strictMode) > 0 {
		strict = strictMode[0]
	}

	// Case 1: ip is a single IP (not CIDR notation)
	ipObj := net.ParseIP(ip)
	if ipObj != nil {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// cidr is not in CIDR notation — treat as a plain IP
			cidrIP := net.ParseIP(cidr)
			if cidrIP == nil {
				return false
			}
			return ipObj.Equal(cidrIP)
		}
		return ipNet.Contains(ipObj)
	}

	// Case 2: ip is itself a CIDR
	_, ipNet, err := net.ParseCIDR(ip)
	if err != nil {
		return false
	}

	_, cidrNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// cidr is a single IP — check whether it falls inside ipNet
		cidrIP := net.ParseIP(cidr)
		if cidrIP == nil {
			return false
		}
		return ipNet.Contains(cidrIP)
	}

	// Both are CIDRs.
	if ip == cidr {
		return true
	}

	// Get each network's base address for containment checks.
	ipNetStart, _, _ := net.ParseCIDR(ip)
	cidrNetStart, _, _ := net.ParseCIDR(cidr)

	ipMaskSize, _ := ipNet.Mask.Size()
	cidrMaskSize, _ := cidrNet.Mask.Size()

	if strict {
		// Strict: first CIDR must be fully contained in the second.
		return cidrNet.Contains(ipNetStart) && cidrMaskSize <= ipMaskSize
	}

	// Non-strict: any overlap — valid CIDRs are power-of-2 aligned, so overlap
	// always means one network address lies inside the other.
	return cidrNet.Contains(ipNetStart) || ipNet.Contains(cidrNetStart)
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

	// Exclude is a proper subset of base: split and recurse.
	// Use the address-family bit-width so this works for both IPv4 (/32) and IPv6 (/128).
	_, bits := base.Mask.Size()
	if baseMask >= bits {
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
	// Exact match first
	if source, ok := whitelist[ip]; ok {
		return true, ip, source
	}

	// CIDR range check
	for cidr, source := range whitelist {
		if isIPInCIDR(ip, cidr, false) {
			return true, cidr, source
		}
	}

	return false, "", ""
}
