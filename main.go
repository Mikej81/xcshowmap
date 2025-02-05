package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// APIResponse represents the JSON structure of the Load Balancer API response
type APIResponse struct {
	Spec struct {
		AppFirewall struct {
			Name string `json:"name"`
		} `json:"app_firewall"`
		Routes []struct {
			SimpleRoute *struct {
				Path struct {
					Prefix string `json:"prefix"`
					Regex  string `json:"regex"`
				} `json:"path"`
				OriginPools []struct {
					Pool struct {
						Name string `json:"name"`
					} `json:"pool"`
				} `json:"origin_pools"`
			} `json:"simple_route"`
			RedirectRoute *struct {
				Path struct {
					Prefix string `json:"prefix"`
				} `json:"path"`
				RouteRedirect struct {
					HostRedirect string `json:"host_redirect"`
					PathRedirect string `json:"path_redirect"`
				} `json:"route_redirect"`
			} `json:"redirect_route"`
		} `json:"routes"`
		Domains []string `json:"domains"` // <-- ADD THIS LINE
	} `json:"spec"`
}

// OriginPoolResponse represents the API response structure for querying an origin pool
type OriginPoolResponse struct {
	Spec struct {
		Origins []struct {
			Name string `json:"name"`
		} `json:"origins"`
	} `json:"spec"`
}

var httpClient = &http.Client{}

func main() {
	// Define CLI arguments
	apiURL := flag.String("api-url", "", "Base API URL")
	token := flag.String("token", "", "API token for authentication")
	namespace := flag.String("namespace", "", "Namespace to query")
	loadBalancer := flag.String("load-balancer", "", "Load balancer to inspect")
	debug := flag.Bool("debug", false, "Enable debug mode to print raw API response")

	flag.Parse()

	// Validate required arguments
	if *apiURL == "" || *token == "" || *namespace == "" || *loadBalancer == "" {
		fmt.Println("Usage: xcshowmap -api-url <API_URL> -token <TOKEN> -namespace <NAMESPACE> -load-balancer <LB> [-debug]")
		os.Exit(1)
	}

	// Construct API URL
	queryURL := fmt.Sprintf("%s/api/config/namespaces/%s/http_loadbalancers/%s", *apiURL, *namespace, *loadBalancer)

	// Query API
	data, err := queryAPI(queryURL, *token)
	if err != nil {
		fmt.Printf("Error querying API: %v\n", err)
		os.Exit(1)
	}

	// Debug mode: Print raw API response
	if *debug {
		fmt.Println("\n--- API Response (Debug Mode) ---")
		fmt.Println(string(data))
		fmt.Println("--------------------------------")
	}

	// Parse API response
	var apiResponse APIResponse
	if err := json.Unmarshal(data, &apiResponse); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	// Generate and print Mermaid diagram
	generateMermaidDiagram(apiResponse, *apiURL, *token, *namespace, *debug)

}

// queryAPI makes a GET request and returns the response body
func queryAPI(url, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "APIToken "+token)

	resp, err := httpClient.Do(req) // Use global client
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	return ioutil.ReadAll(resp.Body)
}

// queryOriginPool fetches the upstream origins from an origin pool
func queryOriginPool(apiURL, token, namespace, poolName string, debug bool) ([]string, error) {
	queryURL := fmt.Sprintf("%s/api/config/namespaces/%s/origin_pools/%s", apiURL, namespace, poolName)

	data, err := queryAPI(queryURL, token)
	if err != nil {
		return nil, err
	}

	// Debug mode: Print raw Origin Pool API response
	if debug {
		fmt.Printf("\n--- Origin Pool API Response for %s (Debug Mode) ---\n", poolName)
		fmt.Println(string(data))
		fmt.Println("---------------------------------------------------")
	}

	var response struct {
		Spec struct {
			OriginServers []struct {
				PublicIP struct {
					IP string `json:"ip"`
				} `json:"public_ip"`
				PublicName struct {
					DNSName string `json:"dns_name"`
				} `json:"public_name"`
				PrivateIP struct {
					IP string `json:"ip"`
				} `json:"private_ip"`
				PrivateName struct {
					DNSName string `json:"dns_name"`
				} `json:"private_name"`
				K8sService struct {
					ServiceName string `json:"service_name"`
				} `json:"k8s_service"`
				ConsulService struct {
					ServiceName string `json:"service_name"`
				} `json:"consul_service"`
			} `json:"origin_servers"`
		} `json:"spec"`
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&response); err != nil {
		return nil, err
	}

	var origins []string
	for _, server := range response.Spec.OriginServers {
		switch {
		case server.PublicIP.IP != "":
			origins = append(origins, server.PublicIP.IP)
		case server.PublicName.DNSName != "":
			origins = append(origins, server.PublicName.DNSName)
		case server.PrivateIP.IP != "":
			origins = append(origins, server.PrivateIP.IP)
		case server.PrivateName.DNSName != "":
			origins = append(origins, server.PrivateName.DNSName)
		case server.K8sService.ServiceName != "":
			origins = append(origins, server.K8sService.ServiceName)
		case server.ConsulService.ServiceName != "":
			origins = append(origins, server.ConsulService.ServiceName)
		}
	}

	return origins, nil
}

// generateMermaidDiagram outputs a Mermaid diagram from API data
func generateMermaidDiagram(apiResponse APIResponse, apiURL, token, namespace string, debug bool) {
	wafName := apiResponse.Spec.AppFirewall.Name
	if wafName == "" {
		wafName = "WAF Not Configured"
	}

	var sb strings.Builder

	sb.WriteString("\nMermaid Diagram:\n```mermaid\n")
	sb.WriteString("graph LR;\n")
	sb.WriteString("    User -->|SNI| LoadBalancer;\n")

	// Display each domain as a node connected to the Load Balancer
	for _, domain := range apiResponse.Spec.Domains {
		sb.WriteString(fmt.Sprintf("    LoadBalancer -->|%s| %s;\n", domain, domain))
		sb.WriteString(fmt.Sprintf("    %s --> ServicePolicies;\n", domain))
	}

	wafNode := wafName
	sb.WriteString(fmt.Sprintf("    ServicePolicies -->|Processes WAF| %s;\n", wafNode))
	sb.WriteString(fmt.Sprintf("    %s -->|Routes Evaluated| Routes;\n", wafNode))

	for i, route := range apiResponse.Spec.Routes {
		if route.SimpleRoute != nil {
			var path string
			switch {
			case route.SimpleRoute.Path.Prefix != "":
				path = route.SimpleRoute.Path.Prefix
			case route.SimpleRoute.Path.Regex != "":
				path = fmt.Sprintf("\"Regex: %s\"", route.SimpleRoute.Path.Regex)
			default:
				path = "Unknown Route"
			}

			nodeID := fmt.Sprintf("route_%d", i)
			sb.WriteString(fmt.Sprintf("    Routes -->|%s| %s;\n", path, nodeID))

			for _, pool := range route.SimpleRoute.OriginPools {
				poolID := fmt.Sprintf("pool_%s", pool.Pool.Name)
				sb.WriteString(fmt.Sprintf("    %s --> %s;\n", nodeID, poolID))

				origins, err := queryOriginPool(apiURL, token, namespace, pool.Pool.Name, debug)
				if err != nil {
					sb.WriteString(fmt.Sprintf("    // Error fetching origins for %s: %v\n", pool.Pool.Name, err))
					continue
				}
				for _, origin := range origins {
					sb.WriteString(fmt.Sprintf("    %s --> %s;\n", poolID, origin))
				}
			}
		}
		if route.RedirectRoute != nil {
			redirectID := fmt.Sprintf("redirect_%d", i)
			sb.WriteString(fmt.Sprintf("    Routes -->|Redirect: %s| %s;\n", route.RedirectRoute.Path.Prefix, redirectID))
			sb.WriteString(fmt.Sprintf("    %s -->|Redirects to| %s;\n", redirectID, route.RedirectRoute.RouteRedirect.HostRedirect))
		}
	}

	sb.WriteString("```\n")
	fmt.Println(sb.String()) // Print final Mermaid output
}
