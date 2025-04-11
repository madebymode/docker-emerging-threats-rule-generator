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
      name:     "CIDR containing a CIDR",
      ip:       "216.144.248.16/28", // This is a CIDR itself
      cidr:     "216.144.248.0/24",
      expectIn: false, // Our function doesn't check for CIDR containment
    },
    {
      name:     "Same CIDR",
      ip:       "216.144.248.16/28",
      cidr:     "216.144.248.16/28",
      expectIn: true,
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
      result := isIPInCIDR(tt.ip, tt.cidr)
      if result != tt.expectIn {
        t.Errorf("isIPInCIDR(%q, %q) = %v, want %v", tt.ip, tt.cidr, result, tt.expectIn)
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
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      result := isIPWhitelisted(tt.ip, whitelist)
      if result != tt.expectWhitelisted {
        t.Errorf("isIPWhitelisted(%q, whitelist) = %v, want %v", tt.ip, result, tt.expectWhitelisted)
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
