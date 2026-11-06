// Package blocklistfmt is the grammar etr-apply enforces on staged blocklists.
// It lives apart from the generator so the generator's tests can check their
// output against exactly what root accepts.
package blocklistfmt

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// labelPattern matches labels the generator emits (see labelFromSource).
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)

// Validate accepts exactly the generator's output: comments and blank lines,
// one `geo $blocked_source { ... }` block holding a `default "";` line and
// `<ip-or-cidr> <label>;` entries, and nothing after the closing brace. That
// leaves no room for include, log or any other directive. It returns the
// number of entries.
func Validate(data []byte, maxEntries int) (int, error) {
	const (
		beforeGeo = iota
		inGeo
		afterGeo
	)
	state, entries, sawDefault := beforeGeo, 0, false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), 4096)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch {
		case state == beforeGeo && line == "geo $blocked_source {":
			state = inGeo
		case state == inGeo && len(fields) == 2 && fields[0] == "default" && fields[1] == `"";`:
			if sawDefault {
				return 0, fmt.Errorf("line %d: duplicate default", n)
			}
			sawDefault = true
		case state == inGeo && line == "}":
			state = afterGeo
		case state == inGeo && len(fields) == 2 && strings.HasSuffix(fields[1], ";"):
			if err := checkEntry(fields[0], strings.TrimSuffix(fields[1], ";")); err != nil {
				return 0, fmt.Errorf("line %d: %v", n, err)
			}
			if entries++; entries > maxEntries {
				return 0, fmt.Errorf("more than %d entries (ETR_APPLY_MAX_ENTRIES)", maxEntries)
			}
		default:
			// Report the position only: on a hostile file, echoing the line
			// would put attacker-chosen text into root's logs.
			return 0, fmt.Errorf("line %d: unexpected content", n)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("reading blocklist: %v", err)
	}
	if state != afterGeo || !sawDefault {
		return 0, fmt.Errorf("incomplete geo block")
	}
	return entries, nil
}

// checkEntry rejects anything but a plain address or prefix, and prefixes so
// broad that they would block a large share of the internet (including
// 0.0.0.0/0 and ::/0).
func checkEntry(addr, label string) error {
	if !labelPattern.MatchString(label) || label == "0" {
		return fmt.Errorf("invalid label")
	}
	var prefix netip.Prefix
	if strings.Contains(addr, "/") {
		p, err := netip.ParsePrefix(addr)
		if err != nil {
			return fmt.Errorf("invalid prefix")
		}
		prefix = p
	} else {
		a, err := netip.ParseAddr(addr)
		if err != nil || a.Zone() != "" {
			return fmt.Errorf("invalid address")
		}
		prefix = netip.PrefixFrom(a, a.BitLen())
	}
	minBits := 8
	switch {
	case prefix.Addr().Is4In6():
		minBits = 96 + 8
	case prefix.Addr().Is6():
		minBits = 16
	}
	if prefix.Bits() < minBits {
		return fmt.Errorf("prefix /%d is broader than /%d", prefix.Bits(), minBits)
	}
	return nil
}
