package main

import (
  "fmt"
  "net/http"
  "net/http/httptest"
  "os"
  "strings"
  "testing"
)

// TestParseIPAddresses tests IP address extraction from various input formats
func TestParseIPAddresses(t *testing.T) {
  tests := []struct {
    name     string
    content  string
    expected []string
  }{
    {
      name: "Single IP addresses",
      content: `192.168.1.1
                10.0.0.1
                172.16.0.1`,
      expected: []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
    },
    {
      name: "CIDR ranges",
      content: `192.168.1.0/24
                10.0.0.0/8
                172.16.0.0/16`,
      expected: []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/16"},
    },
    {
      name: "Mixed IPs and CIDRs",
      content: `192.168.1.1
                10.0.0.0/8
                # Comment line
                172.16.0.1
                216.144.248.16/28`,
      expected: []string{"192.168.1.1", "10.0.0.0/8", "172.16.0.1", "216.144.248.16/28"},
    },
    {
      name: "IPs with inline comments",
      content: `192.168.1.1 # Internal server
                10.0.0.1    ; Another format
                172.16.0.1  // C++ style comment`,
      expected: []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
    },
    {
      name: "Emerging threats format",
      content: `# Emerging Threats Rule Generator
                DROP 192.168.1.1
                REJECT 10.0.0.1
                alert tcp 172.16.0.1 any -> any any`,
      expected: []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
    },
    {
      name: "Empty lines and comments only",
      content: `# This is a comment

              # Another comment

              `,
      expected: []string{},
    },
    {
      name: "Invalid IP addresses",
      content: `999.999.999.999
                192.168.1
                not.an.ip.address
                192.168.1.1`,
      expected: []string{"999.999.999.999", "192.168.1.1"},
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      result := parseIPAddresses(tt.content)

      // Check that all expected IPs are present
      for _, expectedIP := range tt.expected {
        if _, found := result[expectedIP]; !found {
          t.Errorf("Expected IP %s not found in result", expectedIP)
        }
      }

      // Check that result doesn't contain unexpected IPs
      if len(result) != len(tt.expected) {
        resultSlice := make([]string, 0, len(result))
        for ip := range result {
          resultSlice = append(resultSlice, ip)
        }
        t.Errorf("Expected %d IPs, got %d. Expected: %v, Got: %v",
          len(tt.expected), len(result), tt.expected, resultSlice)
      }
    })
  }
}

// TestDownloadFile tests HTTP download functionality with mock server
func TestDownloadFile(t *testing.T) {
  tests := []struct {
    name           string
    responseBody   string
    responseCode   int
    expectedError  bool
    expectedResult string
  }{
    {
      name:           "Successful download",
      responseBody:   "192.168.1.1\n10.0.0.1\n",
      responseCode:   200,
      expectedError:  false,
      expectedResult: "192.168.1.1\n10.0.0.1\n",
    },
    {
      name:          "404 error",
      responseBody:  "Not found",
      responseCode:  404,
      expectedError: true,
    },
    {
      name:          "500 error",
      responseBody:  "Internal server error",
      responseCode:  500,
      expectedError: true,
    },
    {
      name:           "Empty response",
      responseBody:   "",
      responseCode:   200,
      expectedError:  false,
      expectedResult: "",
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      // Create a test server
      server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(tt.responseCode)
        w.Write([]byte(tt.responseBody))
      }))
      defer server.Close()

      // Test the download function
      result, err := downloadFile(server.URL)

      if tt.expectedError {
        if err == nil {
          t.Errorf("Expected error but got none")
        }
      } else {
        if err != nil {
          t.Errorf("Unexpected error: %v", err)
        }
        if result != tt.expectedResult {
          t.Errorf("Expected result %q, got %q", tt.expectedResult, result)
        }
      }
    })
  }
}

// TestWriteBlocklistFile tests nginx configuration file generation
func TestWriteBlocklistFile(t *testing.T) {
  tests := []struct {
    name               string
    whitelist          map[string]struct{}
    blocklist          map[string]struct{}
    expectedContains   []string
    expectedNotContain []string
  }{
    {
      name: "Basic blocklist with whitelist filtering",
      whitelist: map[string]struct{}{
        "192.168.1.1": {},
        "10.0.0.0/8":  {},
      },
      blocklist: map[string]struct{}{
        "192.168.1.1": {}, // Should be filtered out
        "10.1.2.3":    {}, // Should be filtered out (in 10.0.0.0/8)
        "172.16.0.1":  {}, // Should be included
        "8.8.8.8":     {}, // Should be included
      },
      expectedContains: []string{
        "geo $blocked_ip",
        "default        0;",
        "172.16.0.1    1;",
        "8.8.8.8    1;",
      },
      expectedNotContain: []string{
        "192.168.1.1    1;",
        "10.1.2.3    1;",
      },
    },
    {
      name: "CIDR ranges in blocklist",
      whitelist: map[string]struct{}{
        "216.144.248.16/28": {},
      },
      blocklist: map[string]struct{}{
        "216.144.248.0/24":  {}, // Larger CIDR overlaps with whitelist, gets filtered
        "216.144.248.16/30": {}, // Smaller CIDR within whitelist, should be filtered
        "192.168.0.0/16":    {}, // Should be included
      },
      expectedContains: []string{
        "192.168.0.0/16    1;",
      },
      expectedNotContain: []string{
        "216.144.248.0/24    1;",  // Gets filtered due to overlap
        "216.144.248.16/30    1;", // Gets filtered due to overlap
      },
    },
    {
      name:      "Empty lists",
      whitelist: map[string]struct{}{},
      blocklist: map[string]struct{}{},
      expectedContains: []string{
        "geo $blocked_ip",
        "default        0;",
      },
      expectedNotContain: []string{},
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      // Create temporary file
      tmpFile, err := os.CreateTemp("", "blocklist-test-*.conf")
      if err != nil {
        t.Fatalf("Failed to create temp file: %v", err)
      }
      defer os.Remove(tmpFile.Name())
      defer tmpFile.Close()

      // Write blocklist file
      err = writeBlocklistFile(tt.whitelist, tt.blocklist, tmpFile.Name())
      if err != nil {
        t.Fatalf("Failed to write blocklist file: %v", err)
      }

      // Read the generated file
      content, err := os.ReadFile(tmpFile.Name())
      if err != nil {
        t.Fatalf("Failed to read blocklist file: %v", err)
      }

      contentStr := string(content)

      // Check expected content is present
      for _, expected := range tt.expectedContains {
        if !strings.Contains(contentStr, expected) {
          t.Errorf("Expected content %q not found in generated file", expected)
        }
      }

      // Check unwanted content is not present
      for _, notExpected := range tt.expectedNotContain {
        if strings.Contains(contentStr, notExpected) {
          t.Errorf("Unwanted content %q found in generated file", notExpected)
        }
      }

      // Verify basic nginx geo structure
      if !strings.HasPrefix(contentStr, "# blocklist.conf") {
        t.Errorf("File should start with comment header")
      }
      if !strings.HasSuffix(strings.TrimSpace(contentStr), "}") {
        t.Errorf("File should end with closing brace")
      }
    })
  }
}

// TestBlocklistIntegration tests the complete blocklist generation workflow
func TestBlocklistIntegration(t *testing.T) {
  // Create mock HTTP servers for remote lists
  whitelistServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "# Whitelist")
    fmt.Fprintln(w, "192.168.1.0/24")
    fmt.Fprintln(w, "10.0.0.1")
  }))
  defer whitelistServer.Close()

  blocklistServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "# Emerging threats")
    fmt.Fprintln(w, "192.168.1.100") // Should be whitelisted
    fmt.Fprintln(w, "172.16.0.1")    // Should be blocked
    fmt.Fprintln(w, "10.0.0.1")      // Should be whitelisted
    fmt.Fprintln(w, "8.8.8.8")       // Should be blocked
  }))
  defer blocklistServer.Close()

  // Simulate the main workflow
  // 1. Build whitelist
  whitelist := make(map[string]struct{})

  // Add local whitelist entries
  localWhitelist := []string{"172.16.1.1"}
  for _, ip := range localWhitelist {
    whitelist[ip] = struct{}{}
  }

  // Add remote whitelist entries
  whitelistContent, err := downloadFile(whitelistServer.URL)
  if err != nil {
    t.Fatalf("Failed to download whitelist: %v", err)
  }
  whitelistAddresses := parseIPAddresses(whitelistContent)
  for address := range whitelistAddresses {
    whitelist[address] = struct{}{}
  }

  // 2. Build blocklist
  blocklist := make(map[string]struct{})

  // Add local blocklist entries
  localBlocklist := []string{"203.0.113.1"}
  for _, ip := range localBlocklist {
    blocklist[ip] = struct{}{}
  }

  // Add remote blocklist entries
  blocklistContent, err := downloadFile(blocklistServer.URL)
  if err != nil {
    t.Fatalf("Failed to download blocklist: %v", err)
  }
  blocklistAddresses := parseIPAddresses(blocklistContent)
  for address := range blocklistAddresses {
    blocklist[address] = struct{}{}
  }

  // 3. Generate nginx config
  tmpFile, err := os.CreateTemp("", "integration-test-*.conf")
  if err != nil {
    t.Fatalf("Failed to create temp file: %v", err)
  }
  defer os.Remove(tmpFile.Name())
  defer tmpFile.Close()

  err = writeBlocklistFile(whitelist, blocklist, tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to write blocklist file: %v", err)
  }

  // 4. Verify results
  content, err := os.ReadFile(tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to read generated file: %v", err)
  }

  contentStr := string(content)

  // Should be blocked (not in whitelist)
  expectedBlocked := []string{"172.16.0.1", "8.8.8.8", "203.0.113.1"}
  for _, ip := range expectedBlocked {
    pattern := fmt.Sprintf("    %s    1;", ip)
    if !strings.Contains(contentStr, pattern) {
      t.Errorf("IP %s should be blocked but not found in config", ip)
    }
  }

  // Should NOT be blocked (whitelisted)
  expectedWhitelisted := []string{"192.168.1.100", "10.0.0.1", "172.16.1.1"}
  for _, ip := range expectedWhitelisted {
    pattern := fmt.Sprintf("    %s    1;", ip)
    if strings.Contains(contentStr, pattern) {
      t.Errorf("IP %s should be whitelisted but found in blocklist config", ip)
    }
  }
}

// TestBlocklistEdgeCases tests edge cases in blocklist generation
func TestBlocklistEdgeCases(t *testing.T) {
  tests := []struct {
    name      string
    whitelist map[string]struct{}
    blocklist map[string]struct{}
    testCase  string
  }{
    {
      name: "Overlapping CIDR ranges",
      whitelist: map[string]struct{}{
        "192.168.0.0/16": {}, // Large range
      },
      blocklist: map[string]struct{}{
        "192.168.1.0/24": {}, // Smaller range within whitelist
        "10.0.0.0/8":     {}, // Non-overlapping range
      },
      testCase: "CIDR_overlap",
    },
    {
      name: "Exact IP vs CIDR containing it",
      whitelist: map[string]struct{}{
        "192.168.1.1": {}, // Exact IP
      },
      blocklist: map[string]struct{}{
        "192.168.1.0/30": {}, // CIDR containing the whitelisted IP
      },
      testCase: "IP_vs_CIDR",
    },
    {
      name: "Multiple overlapping whitelist ranges",
      whitelist: map[string]struct{}{
        "192.168.0.0/16": {},
        "192.168.1.0/24": {},
        "192.168.1.1":    {},
      },
      blocklist: map[string]struct{}{
        "192.168.1.50": {},
      },
      testCase: "multiple_whitelist",
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      tmpFile, err := os.CreateTemp("", "edge-case-*.conf")
      if err != nil {
        t.Fatalf("Failed to create temp file: %v", err)
      }
      defer os.Remove(tmpFile.Name())
      defer tmpFile.Close()

      err = writeBlocklistFile(tt.whitelist, tt.blocklist, tmpFile.Name())
      if err != nil {
        t.Fatalf("Failed to write blocklist file: %v", err)
      }

      content, err := os.ReadFile(tmpFile.Name())
      if err != nil {
        t.Fatalf("Failed to read blocklist file: %v", err)
      }

      // Basic structure validation
      contentStr := string(content)
      if !strings.Contains(contentStr, "geo $blocked_ip") {
        t.Errorf("Generated file missing geo directive")
      }
      if !strings.Contains(contentStr, "default        0;") {
        t.Errorf("Generated file missing default value")
      }

      // Test case specific validations
      switch tt.testCase {
      case "CIDR_overlap":
        // The 192.168.1.0/24 should be filtered out due to whitelist 192.168.0.0/16
        if strings.Contains(contentStr, "192.168.1.0/24    1;") {
          t.Errorf("Overlapping CIDR should be whitelisted")
        }
        // The 10.0.0.0/8 should remain
        if !strings.Contains(contentStr, "10.0.0.0/8    1;") {
          t.Errorf("Non-overlapping CIDR should be blocked")
        }
      case "IP_vs_CIDR":
        // The CIDR containing whitelisted IP should be filtered
        if strings.Contains(contentStr, "192.168.1.0/30    1;") {
          t.Errorf("CIDR containing whitelisted IP should be filtered")
        }
      case "multiple_whitelist":
        // IP should be whitelisted due to multiple overlapping ranges
        if strings.Contains(contentStr, "192.168.1.50    1;") {
          t.Errorf("IP should be whitelisted by multiple ranges")
        }
      }
    })
  }
}
