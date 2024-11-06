package cloudflaregate

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPTree_Contains(t *testing.T) {
	tests := []struct {
		name     string
		cidrs    []string
		testIP   string
		expected bool
	}{
		{
			name:     "IPv4 exact match",
			cidrs:    []string{"192.168.1.0/24"},
			testIP:   "192.168.1.1",
			expected: true,
		},
		{
			name:     "IPv4 outside range",
			cidrs:    []string{"192.168.1.0/24"},
			testIP:   "192.168.2.1",
			expected: false,
		},
		{
			name:     "IPv6 exact match",
			cidrs:    []string{"2400:cb00::/32"},
			testIP:   "2400:cb00::1",
			expected: true,
		},
		{
			name:     "IPv6 outside range",
			cidrs:    []string{"2400:cb00::/32"},
			testIP:   "2401:cb00::1",
			expected: false,
		},
		{
			name:     "Multiple CIDR ranges",
			cidrs:    []string{"192.168.1.0/24", "10.0.0.0/8"},
			testIP:   "10.0.0.1",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := NewIPTree(nil, "")
			tree.allowedIPs = tt.cidrs
			err := tree.Update()
			if err != nil {
				t.Fatalf("Failed to update tree: %v", err)
			}

			ip := net.ParseIP(tt.testIP)
			if ip == nil {
				t.Fatalf("Failed to parse IP %s", tt.testIP)
			}

			result := tree.Contains(ip)
			if result != tt.expected {
				t.Errorf("Contains(%s) = %v, want %v", tt.testIP, result, tt.expected)
			}
		})
	}
}

func TestIPTree_Update(t *testing.T) {
	tests := []struct {
		name       string
		v4Response string
		v6Response string
		testIPs    []struct {
			ip       string
			expected bool
		}
		expectError bool
	}{
		{
			name:       "normal cloudflare ranges",
			v4Response: "173.245.48.0/20\n103.21.244.0/22\n",
			v6Response: "2400:cb00::/32\n2606:4700::/32\n",
			testIPs: []struct {
				ip       string
				expected bool
			}{
				{"173.245.48.1", true},
				{"103.21.244.1", true},
				{"8.8.8.8", false},
				{"2400:cb00::1", true},
				{"2606:4700::1", true},
				{"2001:4860:4860::8888", false},
			},
			expectError: false,
		},
		{
			name:       "empty responses",
			v4Response: "",
			v6Response: "",
			testIPs: []struct {
				ip       string
				expected bool
			}{
				{"173.245.48.1", false},
				{"2400:cb00::1", false},
			},
			expectError: false,
		},
		{
			name:       "invalid CIDR format",
			v4Response: "invalid-cidr\n173.245.48.0/20\n",
			v6Response: "2400:cb00::/32\n",
			testIPs: []struct {
				ip       string
				expected bool
			}{
				{"173.245.48.1", true},
				{"2400:cb00::1", true},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var response string
				switch r.URL.Path {
				case "/ips-v4":
					response = tt.v4Response
				case "/ips-v6":
					response = tt.v6Response
				default:
					t.Errorf("Unexpected request to %s", r.URL.Path)
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte(response)); err != nil {
					t.Fatalf("Failed to write response: %v", err)
				}
			}))
			defer mockServer.Close()

			tree := NewIPTree(mockServer.Client(), mockServer.URL)
			err := tree.Update()

			if (err != nil) != tt.expectError {
				t.Errorf("Update() error = %v, expectError %v", err, tt.expectError)
				return
			}

			for _, testIP := range tt.testIPs {
				ip := net.ParseIP(testIP.ip)
				if ip == nil {
					t.Fatalf("Failed to parse IP %s", testIP.ip)
				}

				result := tree.Contains(ip)
				if result != testIP.expected {
					t.Errorf("IP %s: got %v, want %v", testIP.ip, result, testIP.expected)
				}
			}
		})
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode()
	if node == nil {
		t.Error("NewNode() returned nil")
		return
	}
	if node.left != nil || node.right != nil || node.network != nil {
		t.Error("NewNode() should return an empty node")
	}
}

func TestIPTree_SingleIP(t *testing.T) {
	tree := NewIPTree(nil, "")
	tree.allowedIPs = []string{"173.245.48.0/20"}

	err := tree.Update()
	if err != nil {
		t.Fatal(err)
	}

	// Test IP within range
	ip := net.ParseIP("173.245.48.1")
	if !tree.Contains(ip) {
		t.Errorf("Expected IP %s to be in range %s", ip, "173.245.48.0/20")
	}
}

func TestCIDRParsing(t *testing.T) {
	cidr := "173.245.48.0/20"
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}

	testIP := net.ParseIP("173.245.48.1")
	if !network.Contains(testIP) {
		t.Errorf("IP %s should be in CIDR %s", testIP, cidr)
	}
}

func TestRefreshLoop(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response string
		switch r.URL.Path {
		case "/ips-v4":
			response = "192.168.1.0/24\n"
		case "/ips-v6":
			response = "2400:cb00::/32\n"
		default:
			t.Errorf("Unexpected request to %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	defer mockServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &Config{
		StrictMode:      true,
		RefreshInterval: "1s",
		AllowedIPs:      []string{"10.0.0.0/8"},
	}

	handler, err := New(ctx, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}), config, "test")
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	cg, ok := handler.(*CloudflareGate)
	if !ok {
		t.Fatal("Handler is not of type *CloudflareGate")
	}

	// Update the IPTree to use our mock server
	cg.ipTree.client = mockServer.Client()
	cg.ipTree.baseURL = mockServer.URL

	// Force an initial update
	err = cg.ipTree.Update()
	if err != nil {
		t.Fatalf("Failed to perform initial update: %v", err)
	}

	// Wait for at least one refresh
	time.Sleep(2 * time.Second)

	// Test both Cloudflare and custom IPs
	testCases := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},  // Cloudflare IP
		{"10.0.0.1", true},     // Custom IP
		{"172.16.0.1", false},  // Not allowed IP
		{"2400:cb00::1", true}, // Cloudflare IPv6
	}

	for _, tc := range testCases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("Failed to parse IP %s", tc.ip)
		}

		result := cg.ipTree.Contains(ip)
		if result != tc.expected {
			t.Errorf("IP %s: got %v, want %v", tc.ip, result, tc.expected)
		}
	}

	// Clean up
	if err := cg.Close(); err != nil {
		t.Errorf("Failed to close handler: %v", err)
	}
}
