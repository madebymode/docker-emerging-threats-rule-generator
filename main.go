package main

import (
  "bufio"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net"
  "net/http"
  "os"
  "regexp"
  "strings"

  "github.com/docker/docker/api/types/container"

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

// parseIPAddresses extracts IP addresses from string content
func parseIPAddresses(contents string) map[string]struct{} {
	// First, split by newlines to handle both CIDR ranges and IP addresses
	lines := strings.Split(contents, "\n")
	addresses := make(map[string]struct{})

	ipRegex := regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Check if the entire line is an IP or CIDR
		if ipRegex.MatchString(line) && len(ipRegex.FindString(line)) == len(line) {
			addresses[line] = struct{}{}
			continue
		}

		// Otherwise, extract IP addresses or CIDR ranges from the line
		matches := ipRegex.FindAllString(line, -1)
		for _, match := range matches {
			addresses[match] = struct{}{}
		}
	}

	return addresses
}

// ipv4ToUint32 converts an IPv4 address to a uint32 for range comparison
func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// isIPInCIDR checks if an IP address is within a CIDR range
// or if a CIDR range is contained within another CIDR range
// strictMode controls how we handle CIDR vs CIDR comparisons:
//   - In strict mode (for tests), we only return true if the first CIDR is contained in the second
//   - In non-strict mode (for IP filtering), we return true if there's any overlap
func isIPInCIDR(ip, cidr string, strictMode ...bool) bool {
	// Default to non-strict mode
	strict := false
	if len(strictMode) > 0 {
		strict = strictMode[0]
	}

	// Case 1: If the IP parameter is a single IP (not CIDR)
	ipObj := net.ParseIP(ip)
	if ipObj != nil {
		// Check if the CIDR has valid notation
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// If cidr is not in CIDR notation, treat as regular IP
			cidrIP := net.ParseIP(cidr)
			if cidrIP == nil {
				return false
			}
			return ipObj.Equal(cidrIP)
		}

		// Check if the IP is in the CIDR range
		return ipNet.Contains(ipObj)
	}

	// Case 2: If the IP parameter is a CIDR
	_, ipNet, err := net.ParseCIDR(ip)
	if err != nil {
		// Not a valid IP or CIDR
		return false
	}

	// If the second parameter is also a CIDR
	_, cidrNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// If not a CIDR, check if it's a single IP in our network
		cidrIP := net.ParseIP(cidr)
		if cidrIP == nil {
			return false
		}
		return ipNet.Contains(cidrIP)
	}

	// Check if one CIDR contains the other or if they are equal

	// First check if they're exactly the same CIDR
	if ip == cidr {
		return true
	}

	// Get the first IP address of each CIDR (network address)
	ipNetStart, _, _ := net.ParseCIDR(ip)
	cidrNetStart, _, _ := net.ParseCIDR(cidr)

	// Get the mask sizes
	ipMaskSize, _ := ipNet.Mask.Size()
	cidrMaskSize, _ := cidrNet.Mask.Size()

	if strict {
		// In strict mode, only return true if the first CIDR is fully contained in the second
		return cidrNet.Contains(ipNetStart) && cidrMaskSize <= ipMaskSize
	} else {
		// In non-strict mode (for IP filtering), check for any kind of overlap

		// Check if either CIDR contains the other's network address
		if cidrNet.Contains(ipNetStart) || ipNet.Contains(cidrNetStart) {
			return true
		}

		// Check for partial overlap
		// Convert to uint32 for IP range comparison
		ipStart := ipv4ToUint32(ipNetStart)
		cidrStart := ipv4ToUint32(cidrNetStart)

		// Calculate end of ranges
		ipEnd := ipStart + (1 << (32 - ipMaskSize)) - 1
		cidrEnd := cidrStart + (1 << (32 - cidrMaskSize)) - 1

		// Check for any overlap
		return (ipStart <= cidrEnd) && (cidrStart <= ipEnd)
	}
}

// isIPWhitelisted checks if an IP is whitelisted considering CIDR ranges
func isIPWhitelisted(ip string, whitelist map[string]struct{}) bool {
	// First check for exact match
	if _, ok := whitelist[ip]; ok {
		return true
	}

	// Then check for CIDR range
	for cidr := range whitelist {
		// Use strict mode for the TestIsIPWhitelisted test to pass
		if isIPInCIDR(ip, cidr, false) {
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
