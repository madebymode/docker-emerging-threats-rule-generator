package main

import (
  "bufio"
  "encoding/json"
  "fmt"
  "github.com/docker/docker/api/types/container"
  "io/ioutil"
  "net"
  "net/http"
  "os"
  "regexp"

  "github.com/docker/docker/client"
  "golang.org/x/net/context"
)

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
      fmt.Printf("Failed to close file: %v\n", err)
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

// downloadFile fetches content from a specified URL
func downloadFile(url string) (string, error) {
  resp, err := http.Get(url)
  if err != nil {
    return "", err
  }
  defer resp.Body.Close()

  if resp.StatusCode != http.StatusOK {
    return "", fmt.Errorf("error fetching URL %s: status code %d", url, resp.StatusCode)
  }

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return "", err
  }

  return string(body), nil
}

// parseIPAddresses extracts IP addresses from string content using regex
func parseIPAddresses(contents string) map[string]struct{} {
  re := regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?`)
  matches := re.FindAllString(contents, -1)

  addresses := make(map[string]struct{})
  for _, match := range matches {
    addresses[match] = struct{}{}
  }

  return addresses
}

// isIPInCIDR checks if an IP address is within a CIDR range
func isIPInCIDR(ip, cidr string) bool {
  // Check if the IP has CIDR notation
  if _, _, err := net.ParseCIDR(ip); err == nil {
    // If both are CIDR, we can only check for exact match
    return ip == cidr
  }

  // Check if the CIDR has valid notation
  _, ipNet, err := net.ParseCIDR(cidr)
  if err != nil {
    // If cidr is not in CIDR notation, treat as regular IP
    whitelistIP := net.ParseIP(cidr)
    ipToCheck := net.ParseIP(ip)
    if whitelistIP == nil || ipToCheck == nil {
      return false
    }
    return ipToCheck.Equal(whitelistIP)
  }

  // Parse the IP address to check
  ipToCheck := net.ParseIP(ip)
  if ipToCheck == nil {
    return false
  }

  // Check if the IP is in the CIDR range
  return ipNet.Contains(ipToCheck)
}

// isIPWhitelisted checks if an IP is whitelisted considering CIDR ranges
func isIPWhitelisted(ip string, whitelist map[string]struct{}) bool {
  // First check for exact match
  if _, ok := whitelist[ip]; ok {
    return true
  }

  // Then check for CIDR range
  for cidr := range whitelist {
    if isIPInCIDR(ip, cidr) {
      return true
    }
  }

  return false
}

// writeBlocklistFile creates an NGINX configuration file for blocking IPs, considering whitelisted IPs
func writeBlocklistFile(whitelist, blocklist map[string]struct{}, filePath string) error {
  file, err := os.Create(filePath)
  if err != nil {
    return err
  }
  defer func(file *os.File) {
    err := file.Close()
    if err != nil {
      fmt.Printf("Failed to close file: %v\n", err)
    }
  }(file)

  writer := bufio.NewWriter(file)
  _, err = writer.WriteString("# blocklist.conf\n\ngeo $blocked_ip {\n    default        0;\n\n")
  if err != nil {
    return err
  }

  for address := range blocklist {
    if !isIPWhitelisted(address, whitelist) {
      _, err = writer.WriteString(fmt.Sprintf("    %s    1;\n", address))
      if err != nil {
        return err
      }
    }
  }

  _, err = writer.WriteString("\n}")
  if err != nil {
    return err
  }

  return writer.Flush()
}

// restartNginxContainers restarts specified Docker containers
func restartNginxContainers(cli *client.Client, containerNames []string) error {
  ctx := context.Background()

  for _, containerName := range containerNames {
    if err := cli.ContainerStop(ctx, containerName, container.StopOptions{}); err != nil {
      return fmt.Errorf("failed to stop container %s: %v", containerName, err)
    }

    if err := cli.ContainerStart(ctx, containerName, container.StartOptions{}); err != nil {
      return fmt.Errorf("failed to start container %s: %v", containerName, err)
    }

    fmt.Printf("Container %s restarted successfully.\n", containerName)
  }

  return nil
}

// main is the entry point for the application
func main() {
  config, err := readConfig("/app/config.json")
  if err != nil {
    fmt.Printf("Failed to read config file: %v\n", err)
    return
  }

  whitelist := make(map[string]struct{})
  for _, address := range config.LocalWhitelist {
    whitelist[address] = struct{}{}
  }

  for _, url := range config.RemoteWhitelists {
    content, err := downloadFile(url)
    if err != nil {
      fmt.Printf("Failed to download file from %s: %v\n", url, err)
      continue
    }

    addresses := parseIPAddresses(content)
    for address := range addresses {
      whitelist[address] = struct{}{}
    }
  }

  blocklist := make(map[string]struct{})
  for _, address := range config.LocalBlocklist {
    blocklist[address] = struct{}{}
  }

  for _, url := range config.RemoteBlocklists {
    content, err := downloadFile(url)
    if err != nil {
      fmt.Printf("Failed to download file from %s: %v\n", url, err)
      continue
    }

    addresses := parseIPAddresses(content)
    for address := range addresses {
      blocklist[address] = struct{}{}
    }
  }

  err = writeBlocklistFile(whitelist, blocklist, config.ConfFilePath)
  if err != nil {
    fmt.Printf("Failed to write blocklist file: %v\n", err)
    return
  }

  cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
  if err != nil {
    fmt.Printf("Failed to create Docker client: %v\n", err)
    return
  }

  if err := restartNginxContainers(cli, config.NginxContainerNames); err != nil {
    fmt.Printf("Failed to restart Nginx containers: %v\n", err)
    return
  }

  fmt.Println("Blocklist.conf file created and Nginx containers restarted successfully.")
}
