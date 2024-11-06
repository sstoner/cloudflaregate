// Package cloudflaregate is a plugin for CloudflareGate.
package cloudflaregate

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	cloudflareURL          = "https://www.cloudflare.com"
	refreshInterval        = 24 * time.Hour
	defaultRefreshInterval = 24 * time.Hour
	minimumRefreshInterval = time.Second
	bitsPerByte            = 8
	lastBitIdx             = bitsPerByte - 1
	maxBitMask             = 1
)

// HTTPClient interface for making HTTP requests.
type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

// Node represents a node in the IP prefix tree.
type Node struct {
	left    *Node      // 0
	right   *Node      // 1
	network *net.IPNet // CIDR if this is a leaf node
}

// IPTree represents a prefix tree for fast IP lookup.
type IPTree struct {
	mu         sync.RWMutex
	v4Root     *Node
	v6Root     *Node
	client     HTTPClient
	baseURL    string
	allowedIPs []string // Store custom allowed IPs
}

// Config the plugin configuration.
type Config struct {
	// StrictMode enables strict mode, which validates cloudflare ip address.
	StrictMode bool `json:"strictMode,omitempty"`
	// RefreshInterval is the interval between IP range updates
	RefreshInterval string `json:"refreshInterval,omitempty"`
	// AllowedIPs is a list of custom IP addresses or CIDR ranges that are allowed
	AllowedIPs []string `json:"allowedIPs,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		StrictMode:      true,
		RefreshInterval: "24h",
	}
}

// CloudflareGate is a CloudflareGate plugin.
type CloudflareGate struct {
	next        http.Handler
	ipTree      *IPTree
	strictMode  bool
	name        string
	stopRefresh chan struct{} // Channel to stop the refresh goroutine
}

// NewNode is a constructor function for Node.
func NewNode() *Node {
	return &Node{}
}

// Contains checks if the given IP address is in the IP prefix tree.
func (t *IPTree) Contains(ip net.IP) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ipv4 := ip.To4()
	root := t.v4Root
	if ipv4 == nil {
		ip = ip.To16()
		root = t.v6Root
	} else {
		ip = ipv4
	}

	current := root
	for i := 0; i < len(ip)*8 && current != nil; i++ {
		if current.network != nil && current.network.Contains(ip) {
			return true
		}

		byteIndex := i / bitsPerByte
		bitIndex := lastBitIdx - (i % bitsPerByte)
		bit := (ip[byteIndex] >> bitIndex) & maxBitMask

		if bit == 0 {
			current = current.left
		} else {
			current = current.right
		}
	}
	return false
}

// Update updates both Cloudflare and custom allowed IP ranges.
func (t *IPTree) Update() error {
	newV4Root := NewNode()
	newV6Root := NewNode()

	// First, add custom allowed IPs
	for _, cidr := range t.allowedIPs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try parsing as a single IP
			ip := net.ParseIP(cidr)
			if ip == nil {
				return fmt.Errorf("invalid IP or CIDR: %s", cidr)
			}
			// Convert single IP to CIDR
			if ip.To4() != nil {
				_, network, _ = net.ParseCIDR(fmt.Sprintf("%s/32", ip))
			} else {
				_, network, _ = net.ParseCIDR(fmt.Sprintf("%s/128", ip))
			}
		}
		t.insertIntoNode(newV4Root, newV6Root, network)
	}

	// Then fetch and add Cloudflare IPs
	if t.baseURL != "" {
		v4URL := t.baseURL + "/ips-v4"
		v6URL := t.baseURL + "/ips-v6"

		v4ranges, err := t.fetchRanges(v4URL)
		if err != nil {
			return err
		}

		v6ranges, err := t.fetchRanges(v6URL)
		if err != nil {
			return err
		}

		// Add Cloudflare IPv4 ranges
		for _, cidr := range v4ranges {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			t.insertIntoNode(newV4Root, newV6Root, network)
		}

		// Add Cloudflare IPv6 ranges
		for _, cidr := range v6ranges {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			t.insertIntoNode(newV4Root, newV6Root, network)
		}
	}

	// Atomically swap the new trees in
	t.mu.Lock()
	t.v4Root = newV4Root
	t.v6Root = newV6Root
	t.mu.Unlock()

	return nil
}

// insertIntoNode inserts a network into the appropriate tree.
func (t *IPTree) insertIntoNode(v4Root, v6Root *Node, network *net.IPNet) {
	ip := network.IP.To4()
	root := v4Root
	if ip == nil {
		ip = network.IP.To16()
		root = v6Root
	}

	ones, _ := network.Mask.Size()
	current := root
	for i := range ones {
		byteIndex := i / bitsPerByte
		bitIndex := lastBitIdx - (i % bitsPerByte)
		bit := (ip[byteIndex] >> bitIndex) & 1

		if bit == 0 {
			if current.left == nil {
				current.left = NewNode()
			}
			current = current.left
		} else {
			if current.right == nil {
				current.right = NewNode()
			}
			current = current.right
		}
	}
	current.network = network
}

// UpdateAllowedIPs updates the custom allowed IP list and refreshes the tree.
func (t *IPTree) UpdateAllowedIPs(newAllowedIPs []string) error {
	t.allowedIPs = newAllowedIPs
	return t.Update()
}

// New created a new CloudflareGate plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Parse refresh interval
	refreshInterval := defaultRefreshInterval
	if config.RefreshInterval != "" {
		interval, err := time.ParseDuration(config.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid refresh interval: %w", err)
		}
		if interval < minimumRefreshInterval {
			return nil, fmt.Errorf("refresh interval must be at least %v", minimumRefreshInterval)
		}
		refreshInterval = interval
	}

	ipTree := NewIPTree(http.DefaultClient, cloudflareURL)
	ipTree.allowedIPs = config.AllowedIPs

	// Initial update
	if err := ipTree.Update(); err != nil {
		return nil, fmt.Errorf("failed to initialize IP ranges: %w", err)
	}

	cg := &CloudflareGate{
		ipTree:      ipTree,
		strictMode:  config.StrictMode,
		next:        next,
		name:        name,
		stopRefresh: make(chan struct{}),
	}

	// Start background refresh with configured interval
	go cg.refreshLoop(ctx, refreshInterval)

	return cg, nil
}

func (cg *CloudflareGate) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	remoteIP := net.ParseIP(strings.Split(req.RemoteAddr, ":")[0])
	if remoteIP == nil || !cg.ipTree.Contains(remoteIP) {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	if !cg.strictMode {
		cg.next.ServeHTTP(rw, req)
		return
	}

	// check request source ip
	cfConnectingIP := net.ParseIP(strings.Split(req.RemoteAddr, ":")[0])
	// CF-Connecting-IP is the IP address of the client connecting to Cloudflare's network
	// cfConnectingIP := net.ParseIP(req.Header.Get("CF-Connecting-IP"))
	if cfConnectingIP == nil || !cg.ipTree.Contains(cfConnectingIP) {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	cg.next.ServeHTTP(rw, req)
}

// NewIPTree is a constructor function for IPTree.
func NewIPTree(client HTTPClient, baseURL string) *IPTree {
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = "https://www.cloudflare.com"
	}
	return &IPTree{
		v4Root:  NewNode(),
		v6Root:  NewNode(),
		client:  client,
		baseURL: baseURL,
	}
}

// refreshLoop periodically updates the IP ranges.
func (cg *CloudflareGate) refreshLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cg.stopRefresh:
			return
		case <-ticker.C:
			if err := cg.ipTree.Update(); err != nil {
				log.Printf("Failed to update Cloudflare IP ranges: %v", err)
			}
		}
	}
}

// Close stops the refresh goroutine.
func (cg *CloudflareGate) Close() error {
	close(cg.stopRefresh)
	return nil
}

// fetchRanges fetches IP ranges from the given URL.
func (t *IPTree) fetchRanges(url string) ([]string, error) {
	if t.client == nil || t.baseURL == "" {
		return nil, nil // Return empty if no client or URL is configured
	}

	resp, err := t.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IP ranges: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var ranges []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		cidr := strings.TrimSpace(scanner.Text())
		if cidr != "" {
			ranges = append(ranges, cidr)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	return ranges, nil
}
