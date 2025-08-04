package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestReadConfig tests configuration file parsing
func TestReadConfig(t *testing.T) {
	tests := []struct {
		name           string
		configContent  string
		expectedConfig *Config
		expectError    bool
	}{
		{
			name: "Valid complete configuration",
			configContent: `{
				"local_whitelist": ["192.168.1.1", "10.0.0.0/8"],
				"local_blocklist": ["172.16.0.1", "203.0.113.0/24"],
				"remote_whitelists": ["https://example.com/whitelist.txt"],
				"remote_blocklists": ["https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"],
				"nginx_conf_file_path": "/app/nginx/conf/blocklist.conf",
				"nginx_container_names": ["nginx1", "nginx2"]
			}`,
			expectedConfig: &Config{
				LocalWhitelist:      []string{"192.168.1.1", "10.0.0.0/8"},
				LocalBlocklist:      []string{"172.16.0.1", "203.0.113.0/24"},
				RemoteWhitelists:    []string{"https://example.com/whitelist.txt"},
				RemoteBlocklists:    []string{"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"},
				ConfFilePath:        "/app/nginx/conf/blocklist.conf",
				NginxContainerNames: []string{"nginx1", "nginx2"},
			},
			expectError: false,
		},
		{
			name: "Minimal valid configuration",
			configContent: `{
				"nginx_conf_file_path": "/app/nginx/conf/blocklist.conf",
				"nginx_container_names": ["nginx1"]
			}`,
			expectedConfig: &Config{
				LocalWhitelist:      nil,
				LocalBlocklist:      nil,
				RemoteWhitelists:    nil,
				RemoteBlocklists:    nil,
				ConfFilePath:        "/app/nginx/conf/blocklist.conf",
				NginxContainerNames: []string{"nginx1"},
			},
			expectError: false,
		},
		{
			name: "Configuration with empty arrays",
			configContent: `{
				"local_whitelist": [],
				"local_blocklist": [],
				"remote_whitelists": [],
				"remote_blocklists": [],
				"nginx_conf_file_path": "/app/nginx/conf/blocklist.conf",
				"nginx_container_names": []
			}`,
			expectedConfig: &Config{
				LocalWhitelist:      []string{},
				LocalBlocklist:      []string{},
				RemoteWhitelists:    []string{},
				RemoteBlocklists:    []string{},
				ConfFilePath:        "/app/nginx/conf/blocklist.conf",
				NginxContainerNames: []string{},
			},
			expectError: false,
		},
		{
			name: "Real-world configuration example",
			configContent: `{
				"local_whitelist": [
					"104.131.107.63",
					"122.248.234.23",
					"216.144.248.16/28",
					"216.245.221.80/28"
				],
				"remote_blocklists": [
					"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
					"https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
				],
				"nginx_conf_file_path": "/app/nginx/conf/blocklist.conf",
				"nginx_container_names": [
					"docker-emerging-threats-rule-generator-nginx-blacklist-1",
					"docker-emerging-threats-rule-generator-nginx-blacklist-2"
				]
			}`,
			expectedConfig: &Config{
				LocalWhitelist: []string{
					"104.131.107.63",
					"122.248.234.23",
					"216.144.248.16/28",
					"216.245.221.80/28",
				},
				LocalBlocklist:   nil,
				RemoteWhitelists: nil,
				RemoteBlocklists: []string{
					"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
					"https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
				},
				ConfFilePath: "/app/nginx/conf/blocklist.conf",
				NginxContainerNames: []string{
					"docker-emerging-threats-rule-generator-nginx-blacklist-1",
					"docker-emerging-threats-rule-generator-nginx-blacklist-2",
				},
			},
			expectError: false,
		},
		{
			name:          "Invalid JSON",
			configContent: `{"invalid": json}`,
			expectError:   true,
		},
		{
			name:          "Empty file",
			configContent: ``,
			expectError:   true,
		},
		{
			name: "Wrong data types",
			configContent: `{
				"local_whitelist": "should be array",
				"nginx_conf_file_path": "/app/nginx/conf/blocklist.conf",
				"nginx_container_names": ["nginx1"]
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpFile, err := os.CreateTemp("", "config-test-*.json")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			// Write config content
			if _, err := tmpFile.WriteString(tt.configContent); err != nil {
				t.Fatalf("Failed to write config content: %v", err)
			}
			if err := tmpFile.Close(); err != nil {
				t.Fatalf("Failed to close temp file: %v", err)
			}

			// Test readConfig function
			config, err := readConfig(tmpFile.Name())

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Compare configurations
			if !reflect.DeepEqual(config, tt.expectedConfig) {
				t.Errorf("Config mismatch.\nExpected: %+v\nGot: %+v", tt.expectedConfig, config)
			}
		})
	}
}

// TestReadConfigFileNotFound tests handling of missing config file
func TestReadConfigFileNotFound(t *testing.T) {
	config, err := readConfig("/nonexistent/config.json")

	if err == nil {
		t.Errorf("Expected error for nonexistent file")
	}

	if config != nil {
		t.Errorf("Expected nil config for nonexistent file")
	}
}

// TestConfigJSONMarshalUnmarshal tests JSON serialization/deserialization
func TestConfigJSONMarshalUnmarshal(t *testing.T) {
	originalConfig := &Config{
		LocalWhitelist:      []string{"192.168.1.1", "10.0.0.0/8"},
		LocalBlocklist:      []string{"172.16.0.1"},
		RemoteWhitelists:    []string{"https://example.com/whitelist.txt"},
		RemoteBlocklists:    []string{"https://example.com/blocklist.txt"},
		ConfFilePath:        "/app/nginx/conf/blocklist.conf",
		NginxContainerNames: []string{"nginx1", "nginx2"},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(originalConfig)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Unmarshal back to Config
	var unmarshaledConfig Config
	err = json.Unmarshal(jsonData, &unmarshaledConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Compare
	if !reflect.DeepEqual(originalConfig, &unmarshaledConfig) {
		t.Errorf("Marshal/unmarshal mismatch.\nOriginal: %+v\nUnmarshaled: %+v", originalConfig, &unmarshaledConfig)
	}
}

// TestConfigValidation tests configuration validation logic
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name           string
		config         *Config
		expectedErrors []string
	}{
		{
			name: "Valid configuration",
			config: &Config{
				LocalWhitelist:      []string{"192.168.1.1"},
				LocalBlocklist:      []string{"10.0.0.1"},
				RemoteWhitelists:    []string{"https://example.com/whitelist.txt"},
				RemoteBlocklists:    []string{"https://example.com/blocklist.txt"},
				ConfFilePath:        "/app/nginx/conf/blocklist.conf",
				NginxContainerNames: []string{"nginx1"},
			},
			expectedErrors: []string{},
		},
		{
			name: "Missing required fields",
			config: &Config{
				LocalWhitelist: []string{"192.168.1.1"},
			},
			expectedErrors: []string{
				"nginx_conf_file_path is required",
				"nginx_container_names is required",
			},
		},
		{
			name: "Invalid IP addresses",
			config: &Config{
				LocalWhitelist:      []string{"invalid-ip", "300.300.300.300"},
				LocalBlocklist:      []string{"192.168.1.1", "not-an-ip"},
				ConfFilePath:        "/app/nginx/conf/blocklist.conf",
				NginxContainerNames: []string{"nginx1"},
			},
			expectedErrors: []string{
				"invalid IP in local_whitelist: invalid-ip",
				"invalid IP in local_whitelist: 300.300.300.300",
				"invalid IP in local_blocklist: not-an-ip",
			},
		},
		{
			name: "Invalid URLs",
			config: &Config{
				RemoteWhitelists:    []string{"not-a-url", "ftp://invalid-scheme.com"},
				RemoteBlocklists:    []string{"https://valid.com", "invalid-url"},
				ConfFilePath:        "/app/nginx/conf/blocklist.conf",
				NginxContainerNames: []string{"nginx1"},
			},
			expectedErrors: []string{
				"invalid URL in remote_whitelists: not-a-url",
				"invalid URL in remote_whitelists: ftp://invalid-scheme.com",
				"invalid URL in remote_blocklists: invalid-url",
			},
		},
		{
			name: "Empty container names",
			config: &Config{
				ConfFilePath:        "/app/nginx/conf/blocklist.conf",
				NginxContainerNames: []string{},
			},
			expectedErrors: []string{
				"nginx_container_names cannot be empty",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateConfig(tt.config)

			if len(errors) != len(tt.expectedErrors) {
				t.Errorf("Expected %d errors, got %d", len(tt.expectedErrors), len(errors))
				t.Errorf("Expected: %v", tt.expectedErrors)
				t.Errorf("Got: %v", errors)
				return
			}

			for i, expectedError := range tt.expectedErrors {
				if i < len(errors) && errors[i] != expectedError {
					t.Errorf("Error %d: expected %q, got %q", i, expectedError, errors[i])
				}
			}
		})
	}
}

// validateConfig validates a configuration struct
func validateConfig(config *Config) []string {
	var errors []string

	// Check required fields
	if config.ConfFilePath == "" {
		errors = append(errors, "nginx_conf_file_path is required")
	}

	if config.NginxContainerNames == nil {
		errors = append(errors, "nginx_container_names is required")
	} else if len(config.NginxContainerNames) == 0 {
		errors = append(errors, "nginx_container_names cannot be empty")
	}

	// Validate IP addresses in local whitelist
	for _, ip := range config.LocalWhitelist {
		if !isValidIPOrCIDRForConfig(ip) {
			errors = append(errors, "invalid IP in local_whitelist: "+ip)
		}
	}

	// Validate IP addresses in local blocklist
	for _, ip := range config.LocalBlocklist {
		if !isValidIPOrCIDRForConfig(ip) {
			errors = append(errors, "invalid IP in local_blocklist: "+ip)
		}
	}

	// Validate URLs in remote whitelists
	for _, url := range config.RemoteWhitelists {
		if !isValidURL(url) {
			errors = append(errors, "invalid URL in remote_whitelists: "+url)
		}
	}

	// Validate URLs in remote blocklists
	for _, url := range config.RemoteBlocklists {
		if !isValidURL(url) {
			errors = append(errors, "invalid URL in remote_blocklists: "+url)
		}
	}

	return errors
}

// isValidIPOrCIDRForConfig validates IP addresses and CIDR ranges for config
func isValidIPOrCIDRForConfig(s string) bool {
	// Try parsing as IP first
	if ip := parseIP(s); ip != nil {
		return true
	}

	// Try parsing as CIDR
	if _, _, err := parseCIDR(s); err == nil {
		return true
	}

	return false
}

// isValidURL validates URLs for config
func isValidURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// Helper functions for validation (simplified versions)
func parseIP(s string) []byte {
	// Simplified IP parsing - in real implementation, use net.ParseIP
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return nil
		}
		// Simple numeric check and range validation
		num := 0
		for _, char := range part {
			if char < '0' || char > '9' {
				return nil
			}
			num = num*10 + int(char-'0')
		}
		if num > 255 {
			return nil
		}
	}
	return []byte{1, 2, 3, 4} // dummy return for valid IP
}

func parseCIDR(s string) ([]byte, []byte, error) {
	// Simplified CIDR parsing
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid CIDR")
	}

	if parseIP(parts[0]) == nil {
		return nil, nil, fmt.Errorf("invalid IP in CIDR")
	}

	// Simple subnet mask validation
	if parts[1] == "" {
		return nil, nil, fmt.Errorf("invalid subnet mask")
	}

	return []byte{1, 2, 3, 4}, []byte{255, 255, 255, 0}, nil
}

// TestConfigFieldTypes tests that config fields have correct types
func TestConfigFieldTypes(t *testing.T) {
	configJSON := `{
		"local_whitelist": ["192.168.1.1"],
		"local_blocklist": ["10.0.0.1"],
		"remote_whitelists": ["https://example.com"],
		"remote_blocklists": ["https://example.com"],
		"nginx_conf_file_path": "/path/to/config",
		"nginx_container_names": ["nginx1"]
	}`

	var config Config
	err := json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Check field types
	if config.LocalWhitelist == nil {
		t.Errorf("LocalWhitelist should not be nil")
	}
	if len(config.LocalWhitelist) != 1 || config.LocalWhitelist[0] != "192.168.1.1" {
		t.Errorf("LocalWhitelist has wrong value: %v", config.LocalWhitelist)
	}

	if config.ConfFilePath != "/path/to/config" {
		t.Errorf("ConfFilePath has wrong value: %s", config.ConfFilePath)
	}

	if len(config.NginxContainerNames) != 1 || config.NginxContainerNames[0] != "nginx1" {
		t.Errorf("NginxContainerNames has wrong value: %v", config.NginxContainerNames)
	}
}

// TestConfigDefaults tests default behavior for optional fields
func TestConfigDefaults(t *testing.T) {
	configJSON := `{
		"nginx_conf_file_path": "/path/to/config",
		"nginx_container_names": ["nginx1"]
	}`

	var config Config
	err := json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Check that optional fields are properly handled as nil/empty
	if config.LocalWhitelist != nil {
		t.Errorf("LocalWhitelist should be nil when not specified, got: %v", config.LocalWhitelist)
	}
	if config.LocalBlocklist != nil {
		t.Errorf("LocalBlocklist should be nil when not specified, got: %v", config.LocalBlocklist)
	}
	if config.RemoteWhitelists != nil {
		t.Errorf("RemoteWhitelists should be nil when not specified, got: %v", config.RemoteWhitelists)
	}
	if config.RemoteBlocklists != nil {
		t.Errorf("RemoteBlocklists should be nil when not specified, got: %v", config.RemoteBlocklists)
	}
}

// BenchmarkReadConfig benchmarks configuration reading performance
func BenchmarkReadConfig(b *testing.B) {
	configContent := `{
		"local_whitelist": ["192.168.1.1", "10.0.0.0/8", "172.16.0.0/16"],
		"local_blocklist": ["203.0.113.1", "198.51.100.0/24"],
		"remote_whitelists": ["https://example.com/whitelist1.txt", "https://example.com/whitelist2.txt"],
		"remote_blocklists": ["https://example.com/blocklist1.txt", "https://example.com/blocklist2.txt"],
		"nginx_conf_file_path": "/app/nginx/conf/blocklist.conf",
		"nginx_container_names": ["nginx1", "nginx2", "nginx3"]
	}`

	tmpFile, err := os.CreateTemp("", "bench-config-*.json")
	if err != nil {
		b.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		b.Fatalf("Failed to write config: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		b.Fatalf("Failed to close file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := readConfig(tmpFile.Name())
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}
