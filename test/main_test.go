package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Mock API server to return predefined JSON responses
func mockServer(responseBody string, statusCode int) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(responseBody))
	})
	return httptest.NewServer(handler)
}

// Test queryAPI function
func TestQueryAPI(t *testing.T) {
	mockResp := `{"spec":{"domains":["example.com"]}}`
	server := mockServer(mockResp, http.StatusOK)
	defer server.Close()

	data, err := queryAPI(server.URL, "mock-token")
	if err != nil {
		t.Fatalf("queryAPI() failed: %v", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(data, &apiResp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if len(apiResp.Spec.Domains) != 1 || apiResp.Spec.Domains[0] != "example.com" {
		t.Errorf("Unexpected response data: %+v", apiResp.Spec.Domains)
	}
}

// Test queryOriginPool function
func TestQueryOriginPool(t *testing.T) {
	mockResp := `{
		"spec": {
			"origin_servers": [
				{"private_ip": {"ip": "192.168.1.1", "site_locator": {"site": {"name": "site-A"}}}},
				{"public_ip": {"ip": "8.8.8.8"}},
				{"public_name": {"dns_name": "example.com"}}
			]
		}
	}`

	server := mockServer(mockResp, http.StatusOK)
	defer server.Close()

	origins, err := queryOriginPool(server.URL, "mock-token", "mock-ns", "mock-pool", false)
	if err != nil {
		t.Fatalf("queryOriginPool() failed: %v", err)
	}

	expectedOrigins := []string{
		`"192.168.1.1<br>site-A"`,
		`"8.8.8.8"`,
		`"example.com"`,
	}

	for i, expected := range expectedOrigins {
		if origins[i] != expected {
			t.Errorf("Expected %s but got %s", expected, origins[i])
		}
	}
}

// Test generateMermaidDiagram function
func TestGenerateMermaidDiagram(t *testing.T) {
	apiResponse := APIResponse{
		Spec: struct {
			AppFirewall struct {
				Name string `json:"name"`
			} `json:"app_firewall"`
			DefaultRoutePools []struct {
				Pool struct{ Name string } `json:"pool"`
			} `json:"default_route_pools"`
			ActiveServicePolicies struct {
				Policies []struct{ Namespace, Name string } `json:"policies"`
			} `json:"active_service_policies"`
			Routes []struct {
				SimpleRoute *struct {
					Path struct {
						Prefix string `json:"prefix"`
						Regex  string `json:"regex"`
					} `json:"path"`
					Headers     []struct{ Name, Regex string } `json:"headers,omitempty"`
					OriginPools []struct {
						Pool struct{ Name string } `json:"pool"`
					} `json:"origin_pools"`
					AdvancedOptions *struct {
						AppFirewall  *struct{ Name string } `json:"app_firewall,omitempty"`
						InheritedWAF *struct{}              `json:"inherited_waf,omitempty"`
					} `json:"advanced_options,omitempty"`
				} `json:"simple_route,omitempty"`
				RedirectRoute *struct {
					Path struct {
						Prefix string `json:"prefix"`
					} `json:"path"`
					Headers       []struct{ Name, Regex string } `json:"headers,omitempty"`
					RouteRedirect struct {
						HostRedirect, PathRedirect string `json:"host_redirect", "path_redirect"`
					} `json:"route_redirect"`
				} `json:"redirect_route,omitempty"`
			} `json:"routes"`
			Domains                     []string               `json:"domains"`
			AdvertiseOnPublicDefaultVIP map[string]interface{} `json:"advertise_on_public_default_vip,omitempty"`
			AdvertiseOnPublic           map[string]interface{} `json:"advertise_on_public,omitempty"`
			AdvertiseOnCustom           map[string]interface{} `json:"advertise_on_custom,omitempty"`
		}{
			AppFirewall: struct {
				Name string `json:"name"`
			}{Name: "test-waf"},
			Domains: []string{"example.com"},
			Routes: []struct {
				SimpleRoute *struct {
					Path struct {
						Prefix string `json:"prefix"`
						Regex  string `json:"regex"`
					} `json:"path"`
					Headers     []struct{ Name, Regex string } `json:"headers,omitempty"`
					OriginPools []struct {
						Pool struct{ Name string } `json:"pool"`
					} `json:"origin_pools"`
					AdvancedOptions *struct {
						AppFirewall  *struct{ Name string } `json:"app_firewall,omitempty"`
						InheritedWAF *struct{}              `json:"inherited_waf,omitempty"`
					} `json:"advanced_options,omitempty"`
				} `json:"simple_route,omitempty"`
				RedirectRoute *struct {
					Path struct {
						Prefix string `json:"prefix"`
					} `json:"path"`
					Headers       []struct{ Name, Regex string } `json:"headers,omitempty"`
					RouteRedirect struct {
						HostRedirect, PathRedirect string `json:"host_redirect", "path_redirect"`
					} `json:"route_redirect"`
				} `json:"redirect_route,omitempty"`
			}{
				{SimpleRoute: &struct {
					Path struct {
						Prefix string `json:"prefix"`
						Regex  string `json:"regex"`
					} `json:"path"`
					Headers     []struct{ Name, Regex string } `json:"headers,omitempty"`
					OriginPools []struct {
						Pool struct{ Name string } `json:"pool"`
					} `json:"origin_pools"`
					AdvancedOptions *struct {
						AppFirewall  *struct{ Name string } `json:"app_firewall,omitempty"`
						InheritedWAF *struct{}              `json:"inherited_waf,omitempty"`
					} `json:"advanced_options,omitempty"`
				}{
					Path: struct {
						Prefix string `json:"prefix"`
						Regex  string `json:"regex"`
					}{Prefix: "/test"},
					OriginPools: []struct {
						Pool struct{ Name string } `json:"pool"`
					}{
						{Pool: struct{ Name string }{Name: "test-pool"}},
					},
				}},
			},
		},
	}

	var output bytes.Buffer
	fmt.SetOut(&output) // Capture stdout output
	generateMermaidDiagram(apiResponse, "http://mockapi.com", "mock-token", "mock-namespace", false)

	mermaidOutput := output.String()
	expectedSnippet := "graph LR;\n    User -->|SNI| LoadBalancer;"
	if !strings.Contains(mermaidOutput, expectedSnippet) {
		t.Errorf("Mermaid output is incorrect.\nExpected: %s\nGot: %s", expectedSnippet, mermaidOutput)
	}
}
