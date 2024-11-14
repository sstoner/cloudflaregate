// Package cloudflaregate is a plugin for CloudflareGate.
package cloudflaregate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type contextKey string

const (
	// CTXHTTPTimeout is the context key for the HTTP timeout.
	CTXHTTPTimeout contextKey = "HTTPTimeout"
	// CTXTrustedIPs is the context key for the trusted IP ranges.
	CTXTrustedIPs contextKey = "TrustedIPs"
	// CFAPI is the Cloudflare API URL.
	CFAPI = "https://api.cloudflare.com/client/v4/ips"
	// HTTPTimeoutDefault is the default HTTP timeout in seconds.
	HTTPTimeoutDefault = 5
)

// Config the plugin configuration.
type Config struct {
	// RefreshInterval is the interval between IP range updates
	RefreshInterval string `json:"refreshInterval,omitempty"`
	// AllowedIPs is a list of custom IP addresses or CIDR ranges that are allowed
	AllowedIPs []string `json:"allowedIPs,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		RefreshInterval: "24h",
	}
}

// CloudflareGate is a CloudflareGate plugin.
type CloudflareGate struct {
	next http.Handler

	name string
	ips  *ipstore

	refreshInterval time.Duration
	trustedIPs      []net.IPNet
}

// New created a new CloudflareGate plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	ips := newIPStore(CFAPI)

	refreshInterval, err := time.ParseDuration(config.RefreshInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh interval: %w", err)
	}

	trustedIPs, err := parseCIDRs(config.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trusted IPs: %w", err)
	}

	ctxUpdate := createContext(ctx, HTTPTimeoutDefault, trustedIPs)

	if err := ips.Update(ctxUpdate); err != nil {
		return nil, fmt.Errorf("failed to update Cloudflare IP ranges: %w", err)
	}

	cf := &CloudflareGate{
		next: next,
		name: name,

		ips:             ips,
		trustedIPs:      trustedIPs,
		refreshInterval: refreshInterval,
	}

	go cf.refreshLoop(ctx)
	return cf, nil
}

func (cf *CloudflareGate) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	remoteIP := net.ParseIP(strings.Split(req.RemoteAddr, ":")[0])
	if remoteIP == nil || !cf.ips.Contains(remoteIP) {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	cf.next.ServeHTTP(rw, req)
}

// refreshLoop periodically updates the IP ranges.
func (cf *CloudflareGate) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(cf.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			ctxUpdate := createContext(ctx, HTTPTimeoutDefault, cf.trustedIPs)

			if err := cf.ips.Update(ctxUpdate); err != nil {
				log.Printf("Failed to update Cloudflare IP ranges: %v", err)
			}
		}
	}
}

type ipstore struct {
	cfAPI string
	atomic.Value
}

func newIPStore(cfURL string) *ipstore {
	ips := &ipstore{
		cfAPI: cfURL,
	}
	ips.Store([]net.IPNet{})
	return ips
}

func (ips *ipstore) Contains(ip net.IP) bool {
	cidrs, ok := ips.Load().([]net.IPNet)
	if !ok {
		return false
	}
	for _, ipNet := range cidrs {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// Update fetches the latest Cloudflare IP ranges and updates the store.
func (ips *ipstore) Update(ctx context.Context) error {
	trustedIPs, ok := ctx.Value(CTXTrustedIPs).([]net.IPNet)
	if !ok {
		return errors.New("invalid trusted IPs value")
	}

	fetchedCIDRs, err := ips.fetch(ctx)
	if err != nil {
		return err
	}

	cidrs := make([]net.IPNet, 0, len(trustedIPs)+len(fetchedCIDRs))
	cidrs = append(cidrs, trustedIPs...)
	cidrs = append(cidrs, fetchedCIDRs...)

	ips.Store(cidrs)
	return nil // Return nil if everything is successful
}

func (ips *ipstore) fetch(ctx context.Context) ([]net.IPNet, error) {
	timeout, ok := ctx.Value(CTXHTTPTimeout).(int) // Ensure timeout is of type int
	if !ok {
		return nil, errors.New("invalid timeout value")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ips.cfAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Printf("failed to close response body: %v", err)
		}
	}()

	// Check for a successful response
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", res.Status)
	}

	resp := CFResponse{}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return parseResponse(resp)
}

// CFResponse is a Cloudflare API response.
type CFResponse struct {
	/*
		{
			"result":{
				"ipv4_cidrs":["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"],
				"ipv6_cidrs":["2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32"],
				"etag":"38f79d050aa027e3be3865e495dcc9bc"
				},
			"success":true,
			"errors":[],
			"messages":[]
		}
	*/
	Result   CFResponseResult    `json:"result"`
	Success  bool                `json:"success"`
	Errors   []CFResponseMessage `json:"errors"`
	Messages []CFResponseMessage `json:"messages"`
}

// CFResponseResult is a response result.
type CFResponseResult struct {
	// IPv4CIDRs is a list of IPv4 CIDR ranges that Cloudflare uses.
	IPv4CIDRs []string `json:"ipv4_cidrs"` //nolint:tagliatelle
	// IPv6CIDRs is a list of IPv6 CIDR ranges that Cloudflare uses.
	IPv6CIDRs []string `json:"ipv6_cidrs"` //nolint:tagliatelle
	// ETag is a unique identifier for the response.
	ETag string `json:"etag"`
}

// CFResponseMessage is a response message.
type CFResponseMessage struct {
	// Code is a message code.
	Code int `json:"code"`
	// Message is a human-readable message.
	Message string `json:"message"`
}

func createContext(ctx context.Context, timeout int, trustedIPs []net.IPNet) context.Context {
	ctx = context.WithValue(ctx, CTXHTTPTimeout, timeout)
	return context.WithValue(ctx, CTXTrustedIPs, trustedIPs)
}

func parseResponse(resp CFResponse) ([]net.IPNet, error) {
	ipv4CIDRs, err := parseCIDRs(resp.Result.IPv4CIDRs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPv4 CIDRs: %w", err)
	}
	ipv6CIDRs, err := parseCIDRs(resp.Result.IPv6CIDRs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPv6 CIDRs: %w", err)
	}
	return append(ipv4CIDRs, ipv6CIDRs...), nil
}

func parseCIDRs(ips []string) ([]net.IPNet, error) {
	trustedIPs := make([]net.IPNet, 0, len(ips))
	for _, ip := range ips {
		_, ipNet, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR: %w", err)
		}
		trustedIPs = append(trustedIPs, *ipNet)
	}
	return trustedIPs, nil
}
