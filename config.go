package main

import (
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

// Config struct includes local and remote IP lists for whitelisting and blocklisting
type Config struct {
	LocalWhitelist      []string `json:"local_whitelist"`
	LocalBlocklist      []string `json:"local_blocklist"`
	RemoteWhitelists    []string `json:"remote_whitelists"`
	RemoteBlocklists    []string `json:"remote_blocklists"`
	ConfFilePath        string   `json:"nginx_conf_file_path"`
	NginxContainerNames []string `json:"nginx_container_names"`
	NginxServiceName    string   `json:"nginx_service_name"`
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

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// encoding/json silently drops unknown keys, so a misspelled list name
	// would otherwise disable that list without any sign in the logs.
	for _, key := range unknownConfigKeys(data) {
		logf("Warning: ignoring unknown config key %q in %s\n", key, filePath)
	}

	return config, nil
}

// unknownConfigKeys returns top-level keys in data that map to no Config field.
func unknownConfigKeys(data []byte) []string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	known := make(map[string]bool)
	t := reflect.TypeOf(Config{})
	for i := 0; i < t.NumField(); i++ {
		// encoding/json matches keys case-insensitively; mirror that.
		known[strings.ToLower(strings.Split(t.Field(i).Tag.Get("json"), ",")[0])] = true
	}
	var unknown []string
	for key := range raw {
		if !known[strings.ToLower(key)] {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	return unknown
}
