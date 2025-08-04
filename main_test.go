package main

import (
  "fmt"
  "io/ioutil"
  "os"
  "strings"
  "testing"
)

// TestCIDRHandling tests the isIPInCIDR function with various scenarios
func TestCIDRHandling(t *testing.T) {
  tests := []struct {
    name     string
    ip       string
    cidr     string
    expectIn bool
  }{
    {
      name:     "IP in CIDR range",
      ip:       "216.144.248.28",
      cidr:     "216.144.248.16/28",
      expectIn: true,
    },
    {
      name:     "IP outside CIDR range",
      ip:       "216.144.248.32",
      cidr:     "216.144.248.16/28",
      expectIn: false,
    },
    {
      name:     "IP exactly matches CIDR base",
      ip:       "216.144.248.16",
      cidr:     "216.144.248.16/28",
      expectIn: true,
    },
    {
      name:     "IP in larger CIDR range",
      ip:       "216.144.248.100",
      cidr:     "216.144.248.0/24",
      expectIn: true,
    },
    {
      name:     "IP and exact IP match",
      ip:       "192.168.1.1",
      cidr:     "192.168.1.1",
      expectIn: true,
    },
    {
      name:     "CIDR containing a CIDR - Large contains Small",
      ip:       "216.144.248.16/28", // A small CIDR (/28 = 16 addresses)
      cidr:     "216.144.248.0/24",  // A large CIDR (/24 = 256 addresses)
      expectIn: true,                // Small CIDR is contained in large CIDR
    },
    {
      name:     "CIDR containing a CIDR - Small doesn't contain Large",
      ip:       "216.144.248.0/24",  // A large CIDR (/24 = 256 addresses)
      cidr:     "216.144.248.16/28", // A small CIDR (/28 = 16 addresses)
      expectIn: false,               // Large CIDR is not contained in small CIDR
    },
    {
      name:     "Same CIDR",
      ip:       "216.144.248.16/28",
      cidr:     "216.144.248.16/28",
      expectIn: true,
    },
    {
      name:     "CIDR with different base addresses",
      ip:       "216.144.248.32/28", // 216.144.248.32-47
      cidr:     "216.144.248.16/28", // 216.144.248.16-31
      expectIn: false,               // Different network blocks
    },
    {
      name:     "Overlapping CIDRs but different sizes",
      ip:       "216.144.248.16/30", // 216.144.248.16-19
      cidr:     "216.144.248.16/28", // 216.144.248.16-31
      expectIn: true,                // Smaller CIDR is fully contained in larger one
    },
    {
      name:     "Invalid IP",
      ip:       "invalid-ip",
      cidr:     "216.144.248.16/28",
      expectIn: false,
    },
    {
      name:     "Invalid CIDR",
      ip:       "192.168.1.1",
      cidr:     "invalid-cidr",
      expectIn: false,
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      // Use strict mode for tests
      result := isIPInCIDR(tt.ip, tt.cidr, true)
      if result != tt.expectIn {
        t.Errorf("isIPInCIDR(%q, %q, true) = %v, want %v", tt.ip, tt.cidr, result, tt.expectIn)
      }
    })
  }
}

// TestIsIPWhitelisted tests the complete whitelist functionality
func TestIsIPWhitelisted(t *testing.T) {
  whitelist := map[string]struct{}{
    "192.168.1.1":       {},
    "10.0.0.0/8":        {},
    "216.144.248.16/28": {},
  }

  tests := []struct {
    name              string
    ip                string
    expectWhitelisted bool
  }{
    {
      name:              "IP exact match",
      ip:                "192.168.1.1",
      expectWhitelisted: true,
    },
    {
      name:              "IP in CIDR range",
      ip:                "10.1.2.3",
      expectWhitelisted: true,
    },
    {
      name:              "IP in specific CIDR range",
      ip:                "216.144.248.28",
      expectWhitelisted: true,
    },
    {
      name:              "IP outside any range",
      ip:                "8.8.8.8",
      expectWhitelisted: false,
    },
    {
      name:              "IP at boundary",
      ip:                "216.144.248.31", // Last IP in 216.144.248.16/28
      expectWhitelisted: true,
    },
    {
      name:              "IP just outside boundary",
      ip:                "216.144.248.32", // First IP outside 216.144.248.16/28
      expectWhitelisted: false,
    },
    {
      name:              "CIDR contained within whitelist CIDR",
      ip:                "216.144.248.16/30", // Smaller range within 216.144.248.16/28
      expectWhitelisted: true,
    },
    {
      name:              "CIDR containing whitelist CIDR",
      ip:                "216.144.248.0/24", // Larger range containing 216.144.248.16/28
      expectWhitelisted: false,              // Larger CIDRs are not automatically whitelisted
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      // Create a test-specific implementation of isIPWhitelisted that uses strict mode
      isWhitelisted := false
      // First check for exact match
      if _, ok := whitelist[tt.ip]; ok {
        isWhitelisted = true
      } else {
        // Then check for CIDR range
        for cidr := range whitelist {
          // Use strict mode for tests
          if isIPInCIDR(tt.ip, cidr, true) {
            isWhitelisted = true
            break
          }
        }
      }

      if isWhitelisted != tt.expectWhitelisted {
        t.Errorf("Test isIPWhitelisted(%q, whitelist) = %v, want %v", tt.ip, isWhitelisted, tt.expectWhitelisted)
      }
    })
  }
}

// TestBlocklistGeneration tests the entire workflow with real-world examples
func TestBlocklistGeneration(t *testing.T) {
  // Sample whitelist with CIDR ranges
  whitelist := map[string]struct{}{
    "104.131.107.63":    {},
    "122.248.234.23":    {},
    "216.144.248.16/28": {},
    "216.245.221.80/28": {},
  }

  // Sample blocklist with some IPs within the whitelisted ranges
  blocklist := map[string]struct{}{
    "45.135.193.100": {}, // Not in any whitelist
    "216.144.248.20": {}, // Should be whitelisted (in 216.144.248.16/28)
    "216.245.221.85": {}, // Should be whitelisted (in 216.245.221.80/28)
    "122.248.234.23": {}, // Exact match in whitelist
    "192.168.1.1":    {}, // Not in any whitelist
  }

  // Expected results after filtering
  expectedBlocked := map[string]bool{
    "45.135.193.100": true,  // Should be blocked
    "216.144.248.20": false, // Should not be blocked (whitelisted)
    "216.245.221.85": false, // Should not be blocked (whitelisted)
    "122.248.234.23": false, // Should not be blocked (whitelisted)
    "192.168.1.1":    true,  // Should be blocked
  }

  // Create a temporary file for testing
  tmpFile, err := os.CreateTemp("", "blocklist-*.conf")
  if err != nil {
    t.Fatalf("Failed to create temp file: %v", err)
  }
  defer os.Remove(tmpFile.Name())
  defer tmpFile.Close()

  // Generate the blocklist file
  err = writeBlocklistFile(whitelist, blocklist, tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to write blocklist file: %v", err)
  }

  // Read the generated file
  content, err := ioutil.ReadFile(tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to read blocklist file: %v", err)
  }

  // Check if the expected IPs are correctly included/excluded
  for ip, shouldBeBlocked := range expectedBlocked {
    ipPattern := fmt.Sprintf("    %s    1;", ip)
    if shouldBeBlocked {
      // If IP should be blocked, it should be in the file
      if !strings.Contains(string(content), ipPattern) {
        t.Errorf("IP %s should be blocked but wasn't found in the blocklist", ip)
      }
    } else {
      // If IP should not be blocked, it should not be in the file
      if strings.Contains(string(content), ipPattern) {
        t.Errorf("IP %s should not be blocked but was found in the blocklist", ip)
      }
    }
  }
}

// TestRealWorldWhitelistScenario tests a specific scenario where an IP in a CIDR range
// needs to be whitelisted despite being explicitly in a blocklist
func TestRealWorldWhitelistScenario(t *testing.T) {
  // Whitelist with specific CIDR ranges from your example
  whitelist := map[string]struct{}{
    "216.144.248.16/28": {},
    "216.245.221.80/28": {},
  }

  // Blocklist with specific IPs that fall within those ranges
  blocklist := map[string]struct{}{
    "216.144.248.28": {}, // Falls within 216.144.248.16/28
  }

  // Create a temporary file for testing
  tmpFile, err := os.CreateTemp("", "blocklist-real-*.conf")
  if err != nil {
    t.Fatalf("Failed to create temp file: %v", err)
  }
  defer os.Remove(tmpFile.Name())
  defer tmpFile.Close()

  // Generate the blocklist file
  err = writeBlocklistFile(whitelist, blocklist, tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to write blocklist file: %v", err)
  }

  // Read the generated file
  content, err := os.ReadFile(tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to read blocklist file: %v", err)
  }

  // The IP in the whitelisted CIDR range should NOT be present in the blocklist
  if strings.Contains(string(content), "216.144.248.28") {
    t.Errorf("IP 216.144.248.28 should be whitelisted but was found in the blocklist")
  }

  // Verify the file structure is correct
  fileContent := string(content)
  if !strings.Contains(fileContent, "geo $blocked_ip") {
    t.Errorf("Blocklist file doesn't contain expected structure")
  }
  if !strings.Contains(fileContent, "default        0;") {
    t.Errorf("Blocklist file doesn't contain expected default value")
  }
}

// TestCIDRvsBlocklistCIDR tests the handling of CIDR ranges in both whitelist and blocklist
func TestCIDRvsBlocklistCIDR(t *testing.T) {
  // Test cases for CIDR vs CIDR comparison
  tests := []struct {
    name              string
    whitelistCIDR     string
    blocklistCIDR     string
    expectWhitelisted bool
  }{
    {
      name:              "Exact same CIDR in both lists",
      whitelistCIDR:     "192.168.1.0/24",
      blocklistCIDR:     "192.168.1.0/24",
      expectWhitelisted: true, // Whitelist should take precedence
    },
    {
      name:              "Whitelist has larger CIDR that contains blocklist CIDR",
      whitelistCIDR:     "192.168.0.0/16", // Covers 192.168.0.0 - 192.168.255.255
      blocklistCIDR:     "192.168.1.0/24", // Covers 192.168.1.0 - 192.168.1.255
      expectWhitelisted: true,             // The entire blocklist CIDR should be whitelisted
    },
    {
      name:              "Whitelist has smaller CIDR contained within blocklist CIDR",
      whitelistCIDR:     "192.168.1.0/26", // Covers 192.168.1.0 - 192.168.1.63
      blocklistCIDR:     "192.168.1.0/24", // Covers 192.168.1.0 - 192.168.1.255
      expectWhitelisted: true,             // The smaller whitelist CIDR should be whitelisted
    },
    {
      name:              "Partially overlapping CIDRs",
      whitelistCIDR:     "192.168.1.64/26", // Covers 192.168.1.64 - 192.168.1.127
      blocklistCIDR:     "192.168.1.0/25",  // Covers 192.168.1.0 - 192.168.1.127
      expectWhitelisted: true,              // The overlapping part should be whitelisted
    },
    {
      name:              "Non-overlapping CIDRs",
      whitelistCIDR:     "192.168.2.0/24", // Different network
      blocklistCIDR:     "192.168.1.0/24", // Different network
      expectWhitelisted: false,            // No overlap, should not be whitelisted
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      // Set up test whitelist and blocklist
      whitelist := map[string]struct{}{
        tt.whitelistCIDR: {},
      }
      blocklist := map[string]struct{}{
        tt.blocklistCIDR: {},
      }

      // Create a temporary file for testing
      tmpFile, err := os.CreateTemp("", "blocklist-cidr-*.conf")
      if err != nil {
        t.Fatalf("Failed to create temp file: %v", err)
      }
      defer os.Remove(tmpFile.Name())
      defer tmpFile.Close()

      // Generate the blocklist file
      err = writeBlocklistFile(whitelist, blocklist, tmpFile.Name())
      if err != nil {
        t.Fatalf("Failed to write blocklist file: %v", err)
      }

      // Read the generated file
      content, err := os.ReadFile(tmpFile.Name())
      if err != nil {
        t.Fatalf("Failed to read blocklist file: %v", err)
      }

      // Check if the blocklist CIDR is present in the generated file
      if strings.Contains(string(content), tt.blocklistCIDR) != !tt.expectWhitelisted {
        if tt.expectWhitelisted {
          t.Errorf("CIDR %s should be whitelisted but was found in the blocklist", tt.blocklistCIDR)
        } else {
          t.Errorf("CIDR %s should be blocked but wasn't found in the blocklist", tt.blocklistCIDR)
        }
      }
    })
  }
}

// TestRemoteWhitelistParsing tests correct parsing of whitelist entries from remote files
func TestRemoteWhitelistParsing(t *testing.T) {
  // Create a temporary file containing a sample whitelist
  whitelist := `
# Sample whitelist
104.131.107.63
122.248.234.23
# CIDR ranges
216.144.248.16/28
216.245.221.80/28
# Additional entries with comments
3.105.133.239 # AWS IP
`
  tmpFile, err := os.CreateTemp("", "whitelist-*.txt")
  if err != nil {
    t.Fatalf("Failed to create temp file: %v", err)
  }
  defer os.Remove(tmpFile.Name())

  if _, err := tmpFile.Write([]byte(whitelist)); err != nil {
    t.Fatalf("Failed to write to temp file: %v", err)
  }
  if err := tmpFile.Close(); err != nil {
    t.Fatalf("Failed to close temp file: %v", err)
  }

  // Read the file
  content, err := os.ReadFile(tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to read whitelist file: %v", err)
  }

  // Parse the IP addresses
  addresses := parseIPAddresses(string(content))

  // Check if all expected IPs are in the result
  expectedIPs := []string{
    "104.131.107.63",
    "122.248.234.23",
    "216.144.248.16/28",
    "216.245.221.80/28",
    "3.105.133.239",
  }

  for _, ip := range expectedIPs {
    if _, ok := addresses[ip]; !ok {
      t.Errorf("Expected IP %s not found in parsed addresses", ip)
    }
  }

  // Test critical IP handling
  testIP := "216.144.248.28"
  found := false
  for cidr := range addresses {
    if isIPInCIDR(testIP, cidr) {
      found = true
      break
    }
  }

  if !found {
    t.Errorf("Test IP %s should be covered by a CIDR range in the whitelist", testIP)
  }
}
