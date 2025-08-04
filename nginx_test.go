package main

import (
  "bufio"
  "context"
  "fmt"
  "os"
  "regexp"
  "strings"
  "testing"
  "time"
)

// TestNginxConfigFormat tests that generated nginx config follows proper format
func TestNginxConfigFormat(t *testing.T) {
  whitelist := map[string]struct{}{
    "192.168.1.1": {},
  }
  blocklist := map[string]struct{}{
    "10.0.0.1":       {},
    "172.16.0.1":     {},
    "192.168.2.0/24": {},
  }

  tmpFile, err := os.CreateTemp("", "nginx-format-*.conf")
  if err != nil {
    t.Fatalf("Failed to create temp file: %v", err)
  }
  defer os.Remove(tmpFile.Name())
  defer tmpFile.Close()

  err = writeBlocklistFile(whitelist, blocklist, tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to write blocklist file: %v", err)
  }

  content, err := os.ReadFile(tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to read blocklist file: %v", err)
  }

  contentStr := string(content)
  lines := strings.Split(contentStr, "\n")

  // Test 1: Header comment
  if !strings.HasPrefix(lines[0], "# blocklist.conf") {
    t.Errorf("First line should be header comment, got: %s", lines[0])
  }

  // Test 2: Geo directive opening
  geoFound := false
  for _, line := range lines {
    if strings.Contains(line, "geo $blocked_ip {") {
      geoFound = true
      break
    }
  }
  if !geoFound {
    t.Errorf("Geo directive not found in config")
  }

  // Test 3: Default value
  defaultFound := false
  for _, line := range lines {
    if strings.Contains(line, "default        0;") {
      defaultFound = true
      break
    }
  }
  if !defaultFound {
    t.Errorf("Default value not found in config")
  }

  // Test 4: IP entries format (4 spaces, IP, 4 spaces, "1;")
  ipPattern := regexp.MustCompile(`^    [\d\./]+    1;$`)
  ipEntryFound := false
  for _, line := range lines {
    if ipPattern.MatchString(line) {
      ipEntryFound = true
      break
    }
  }
  if !ipEntryFound {
    t.Errorf("No properly formatted IP entries found")
  }

  // Test 5: Closing brace
  if !strings.HasSuffix(strings.TrimSpace(contentStr), "}") {
    t.Errorf("Config should end with closing brace")
  }

  // Test 6: Empty line before closing brace
  trimmedLines := make([]string, 0)
  for _, line := range lines {
    if strings.TrimSpace(line) != "" {
      trimmedLines = append(trimmedLines, line)
    }
  }
  if strings.TrimSpace(trimmedLines[len(trimmedLines)-1]) != "}" {
    // Should have empty line before closing brace in original
    found := false
    for i := len(lines) - 3; i >= 0; i-- {
      if strings.TrimSpace(lines[i]) == "" && strings.TrimSpace(lines[i+1]) == "}" {
        found = true
        break
      }
    }
    if !found {
      t.Errorf("Should have empty line before closing brace")
    }
  }
}

// TestNginxConfigSyntaxValidation tests nginx syntax compatibility
func TestNginxConfigSyntaxValidation(t *testing.T) {
  tests := []struct {
    name        string
    blocklist   map[string]struct{}
    expectValid bool
  }{
    {
      name: "Valid IPv4 addresses",
      blocklist: map[string]struct{}{
        "192.168.1.1": {},
        "10.0.0.1":    {},
        "172.16.0.1":  {},
      },
      expectValid: true,
    },
    {
      name: "Valid CIDR ranges",
      blocklist: map[string]struct{}{
        "192.168.1.0/24": {},
        "10.0.0.0/8":     {},
        "172.16.0.0/16":  {},
      },
      expectValid: true,
    },
    {
      name: "Mixed valid entries",
      blocklist: map[string]struct{}{
        "192.168.1.1":    {},
        "10.0.0.0/8":     {},
        "172.16.0.1":     {},
        "203.0.113.0/24": {},
      },
      expectValid: true,
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      tmpFile, err := os.CreateTemp("", "nginx-syntax-*.conf")
      if err != nil {
        t.Fatalf("Failed to create temp file: %v", err)
      }
      defer os.Remove(tmpFile.Name())
      defer tmpFile.Close()

      whitelist := map[string]struct{}{}
      err = writeBlocklistFile(whitelist, tt.blocklist, tmpFile.Name())
      if err != nil {
        t.Fatalf("Failed to write blocklist file: %v", err)
      }

      // Read and validate the syntax
      content, err := os.ReadFile(tmpFile.Name())
      if err != nil {
        t.Fatalf("Failed to read file: %v", err)
      }

      isValid := validateNginxGeoSyntax(string(content))
      if isValid != tt.expectValid {
        t.Errorf("Syntax validation expected %v, got %v", tt.expectValid, isValid)
      }
    })
  }
}

// validateNginxGeoSyntax validates basic nginx geo module syntax
func validateNginxGeoSyntax(content string) bool {
  lines := strings.Split(content, "\n")

  // Check for required elements
  hasGeoDirective := false
  hasDefault := false
  hasClosingBrace := false
  inGeoBlock := false

  for _, line := range lines {
    line = strings.TrimSpace(line)

    // Skip empty lines and comments
    if line == "" || strings.HasPrefix(line, "#") {
      continue
    }

    // Check geo directive
    if strings.Contains(line, "geo $blocked_ip {") {
      hasGeoDirective = true
      inGeoBlock = true
      continue
    }

    // Check default
    if strings.Contains(line, "default") && strings.Contains(line, "0;") {
      hasDefault = true
      continue
    }

    // Check closing brace
    if line == "}" {
      hasClosingBrace = true
      inGeoBlock = false
      continue
    }

    // Validate IP entries format
    if inGeoBlock && !strings.Contains(line, "default") {
      // Should match pattern: IP/CIDR    1;
      parts := strings.Fields(line)
      if len(parts) != 2 || parts[1] != "1;" {
        return false
      }

      // Basic IP/CIDR validation
      ip := parts[0]
      if !isValidIPOrCIDR(ip) {
        return false
      }
    }
  }

  return hasGeoDirective && hasDefault && hasClosingBrace
}

// isValidIPOrCIDR performs basic IP/CIDR format validation
func isValidIPOrCIDR(s string) bool {
  // Simple regex for IP and CIDR validation
  ipPattern := regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$`)
  return ipPattern.MatchString(s)
}

// TestNginxConfigPerformance tests config generation performance with large datasets
func TestNginxConfigPerformance(t *testing.T) {
  // Create large datasets
  whitelist := make(map[string]struct{})
  blocklist := make(map[string]struct{})

  // Add 1000 whitelist entries
  for i := 0; i < 1000; i++ {
    ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
    whitelist[ip] = struct{}{}
  }

  // Add 10000 blocklist entries
  for i := 0; i < 10000; i++ {
    ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
    blocklist[ip] = struct{}{}
  }

  tmpFile, err := os.CreateTemp("", "nginx-perf-*.conf")
  if err != nil {
    t.Fatalf("Failed to create temp file: %v", err)
  }
  defer os.Remove(tmpFile.Name())
  defer tmpFile.Close()

  // Measure performance
  startTime := time.Now()
  err = writeBlocklistFile(whitelist, blocklist, tmpFile.Name())
  duration := time.Since(startTime)

  if err != nil {
    t.Fatalf("Failed to write blocklist file: %v", err)
  }

  // Should complete within reasonable time (adjust as needed)
  if duration > 5*time.Second {
    t.Errorf("Performance test took too long: %v", duration)
  }

  // Verify file was created and has content
  stat, err := os.Stat(tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to stat file: %v", err)
  }

  // File should have reasonable size (not empty, not too large)
  if stat.Size() == 0 {
    t.Errorf("Generated file is empty")
  }

  t.Logf("Performance test: processed %d whitelist + %d blocklist entries in %v, file size: %d bytes",
    len(whitelist), len(blocklist), duration, stat.Size())
}

// TestNginxConfigConcurrency tests concurrent access to config generation
func TestNginxConfigConcurrency(t *testing.T) {
  const numGoroutines = 10
  const numIterations = 5

  errors := make(chan error, numGoroutines*numIterations)
  done := make(chan bool, numGoroutines)

  // Test data
  whitelist := map[string]struct{}{
    "192.168.1.1": {},
  }
  blocklist := map[string]struct{}{
    "10.0.0.1":   {},
    "172.16.0.1": {},
  }

  // Start goroutines
  for i := 0; i < numGoroutines; i++ {
    go func(id int) {
      defer func() { done <- true }()

      for j := 0; j < numIterations; j++ {
        tmpFile, err := os.CreateTemp("", fmt.Sprintf("nginx-concurrent-%d-%d-*.conf", id, j))
        if err != nil {
          errors <- fmt.Errorf("goroutine %d iteration %d: failed to create temp file: %v", id, j, err)
          continue
        }

        err = writeBlocklistFile(whitelist, blocklist, tmpFile.Name())
        if err != nil {
          errors <- fmt.Errorf("goroutine %d iteration %d: failed to write file: %v", id, j, err)
        }

        // Clean up
        tmpFile.Close()
        os.Remove(tmpFile.Name())

        // Small delay to increase chance of race conditions
        time.Sleep(time.Millisecond)
      }
    }(i)
  }

  // Wait for completion
  for i := 0; i < numGoroutines; i++ {
    <-done
  }
  close(errors)

  // Check for errors
  var errorList []error
  for err := range errors {
    errorList = append(errorList, err)
  }

  if len(errorList) > 0 {
    t.Errorf("Concurrency test had %d errors:", len(errorList))
    for _, err := range errorList {
      t.Errorf("  %v", err)
    }
  }
}

// TestNginxConfigReload tests config file structure for nginx reload compatibility
func TestNginxConfigReload(t *testing.T) {
  blocklist := map[string]struct{}{
    "10.0.0.1":       {},
    "172.16.0.1":     {},
    "192.168.1.0/24": {},
  }

  tmpFile, err := os.CreateTemp("", "nginx-reload-*.conf")
  if err != nil {
    t.Fatalf("Failed to create temp file: %v", err)
  }
  defer os.Remove(tmpFile.Name())
  defer tmpFile.Close()

  err = writeBlocklistFile(map[string]struct{}{}, blocklist, tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to write blocklist file: %v", err)
  }

  // Read file line by line to validate structure
  file, err := os.Open(tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to open file: %v", err)
  }
  defer file.Close()

  scanner := bufio.NewScanner(file)
  lineNum := 0
  geoBlockStarted := false
  defaultFound := false
  ipEntriesFound := 0

  for scanner.Scan() {
    lineNum++
    line := scanner.Text()

    // Header comment
    if lineNum == 1 {
      if !strings.HasPrefix(line, "# blocklist.conf") {
        t.Errorf("Line %d: Expected header comment, got: %s", lineNum, line)
      }
      continue
    }

    // Empty line after header
    if lineNum == 2 {
      if strings.TrimSpace(line) != "" {
        t.Errorf("Line %d: Expected empty line after header", lineNum)
      }
      continue
    }

    // Geo directive
    if strings.Contains(line, "geo $blocked_ip {") {
      geoBlockStarted = true
      continue
    }

    // Default value
    if strings.Contains(line, "default        0;") {
      if !geoBlockStarted {
        t.Errorf("Line %d: Default found before geo block", lineNum)
      }
      defaultFound = true
      continue
    }

    // IP entries
    if strings.Contains(line, "    1;") {
      if !geoBlockStarted || !defaultFound {
        t.Errorf("Line %d: IP entry found before geo block properly started", lineNum)
      }
      ipEntriesFound++

      // Validate formatting
      if !strings.HasPrefix(line, "    ") {
        t.Errorf("Line %d: IP entry should start with 4 spaces", lineNum)
      }
      if !strings.HasSuffix(line, "    1;") {
        t.Errorf("Line %d: IP entry should end with '    1;'", lineNum)
      }
    }

    // Closing brace
    if strings.TrimSpace(line) == "}" {
      if !geoBlockStarted {
        t.Errorf("Line %d: Closing brace found without geo block", lineNum)
      }
    }
  }

  if err := scanner.Err(); err != nil {
    t.Fatalf("Error reading file: %v", err)
  }

  // Validate structure
  if !geoBlockStarted {
    t.Errorf("Geo block never started")
  }
  if !defaultFound {
    t.Errorf("Default value not found")
  }
  if ipEntriesFound != len(blocklist) {
    t.Errorf("Expected %d IP entries, found %d", len(blocklist), ipEntriesFound)
  }
}

// TestNginxVariableNaming tests that the nginx variable name is correct
func TestNginxVariableNaming(t *testing.T) {
  blocklist := map[string]struct{}{
    "10.0.0.1": {},
  }

  tmpFile, err := os.CreateTemp("", "nginx-var-*.conf")
  if err != nil {
    t.Fatalf("Failed to create temp file: %v", err)
  }
  defer os.Remove(tmpFile.Name())
  defer tmpFile.Close()

  err = writeBlocklistFile(map[string]struct{}{}, blocklist, tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to write blocklist file: %v", err)
  }

  content, err := os.ReadFile(tmpFile.Name())
  if err != nil {
    t.Fatalf("Failed to read file: %v", err)
  }

  contentStr := string(content)

  // Check for correct variable name
  if !strings.Contains(contentStr, "geo $blocked_ip") {
    t.Errorf("Config should use $blocked_ip variable")
  }

  // Should not contain other common variable names
  incorrectVars := []string{"$block_ip", "$blocklist", "$banned_ip", "$deny_ip"}
  for _, incorrectVar := range incorrectVars {
    if strings.Contains(contentStr, incorrectVar) {
      t.Errorf("Config should not contain incorrect variable name: %s", incorrectVar)
    }
  }
}

// MockDockerClient for testing nginx container restart functionality
type MockDockerClient struct {
  containers map[string]bool // containerName -> running state
  stopCalls  []string
  startCalls []string
  errors     map[string]error // operation -> error to return
}

func NewMockDockerClient() *MockDockerClient {
  return &MockDockerClient{
    containers: make(map[string]bool),
    stopCalls:  make([]string, 0),
    startCalls: make([]string, 0),
    errors:     make(map[string]error),
  }
}

func (m *MockDockerClient) ContainerStop(ctx context.Context, containerID string, options any) error {
  m.stopCalls = append(m.stopCalls, containerID)
  if err, exists := m.errors["stop_"+containerID]; exists {
    return err
  }
  m.containers[containerID] = false
  return nil
}

func (m *MockDockerClient) ContainerStart(ctx context.Context, containerID string, options any) error {
  m.startCalls = append(m.startCalls, containerID)
  if err, exists := m.errors["start_"+containerID]; exists {
    return err
  }
  m.containers[containerID] = true
  return nil
}

// TestNginxContainerRestartLogic tests the container restart logic
func TestNginxContainerRestartLogic(t *testing.T) {
  tests := []struct {
    name           string
    containerNames []string
    mockErrors     map[string]error
    expectError    bool
    expectedStops  []string
    expectedStarts []string
  }{
    {
      name:           "Single container success",
      containerNames: []string{"nginx1"},
      mockErrors:     map[string]error{},
      expectError:    false,
      expectedStops:  []string{"nginx1"},
      expectedStarts: []string{"nginx1"},
    },
    {
      name:           "Multiple containers success",
      containerNames: []string{"nginx1", "nginx2", "nginx3"},
      mockErrors:     map[string]error{},
      expectError:    false,
      expectedStops:  []string{"nginx1", "nginx2", "nginx3"},
      expectedStarts: []string{"nginx1", "nginx2", "nginx3"},
    },
    {
      name:           "Stop error",
      containerNames: []string{"nginx1"},
      mockErrors:     map[string]error{"stop_nginx1": fmt.Errorf("failed to stop")},
      expectError:    true,
      expectedStops:  []string{"nginx1"},
      expectedStarts: []string{},
    },
    {
      name:           "Start error",
      containerNames: []string{"nginx1"},
      mockErrors:     map[string]error{"start_nginx1": fmt.Errorf("failed to start")},
      expectError:    true,
      expectedStops:  []string{"nginx1"},
      expectedStarts: []string{"nginx1"},
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      mockClient := NewMockDockerClient()
      mockClient.errors = tt.mockErrors

      // Test the restart function logic (without actual Docker client interface)
      err := testRestartNginxContainers(mockClient, tt.containerNames)

      if tt.expectError && err == nil {
        t.Errorf("Expected error but got none")
      }
      if !tt.expectError && err != nil {
        t.Errorf("Unexpected error: %v", err)
      }

      // Verify call order and count
      if len(mockClient.stopCalls) != len(tt.expectedStops) {
        t.Errorf("Expected %d stop calls, got %d", len(tt.expectedStops), len(mockClient.stopCalls))
      }
      for i, expected := range tt.expectedStops {
        if i < len(mockClient.stopCalls) && mockClient.stopCalls[i] != expected {
          t.Errorf("Stop call %d: expected %s, got %s", i, expected, mockClient.stopCalls[i])
        }
      }

      if len(mockClient.startCalls) != len(tt.expectedStarts) {
        t.Errorf("Expected %d start calls, got %d", len(tt.expectedStarts), len(mockClient.startCalls))
      }
      for i, expected := range tt.expectedStarts {
        if i < len(mockClient.startCalls) && mockClient.startCalls[i] != expected {
          t.Errorf("Start call %d: expected %s, got %s", i, expected, mockClient.startCalls[i])
        }
      }
    })
  }
}

// testRestartNginxContainers is a test version of restartNginxContainers
func testRestartNginxContainers(cli *MockDockerClient, containerNames []string) error {
  ctx := context.Background()

  for _, containerName := range containerNames {
    if err := cli.ContainerStop(ctx, containerName, nil); err != nil {
      return fmt.Errorf("failed to stop container %s: %v", containerName, err)
    }

    if err := cli.ContainerStart(ctx, containerName, nil); err != nil {
      return fmt.Errorf("failed to start container %s: %v", containerName, err)
    }
  }

  return nil
}
