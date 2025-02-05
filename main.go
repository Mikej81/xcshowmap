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
		DefaultRoutePools []struct {
			Pool struct {
				Name string `json:"name"`
			} `json:"pool"`
		} `json:"default_route_pools"`
		ActiveServicePolicies struct {
			Policies []struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"policies"`
		} `json:"active_service_policies"`
		Routes []struct {
			SimpleRoute *struct {
				Path struct {
					Prefix string `json:"prefix"`
					Regex  string `json:"regex"`
				} `json:"path"`
				Headers []struct {
					Name  string `json:"name"`
					Regex string `json:"regex,omitempty"`
				} `json:"headers,omitempty"`
				OriginPools []struct {
					Pool struct {
						Name string `json:"name"`
					} `json:"pool"`
				} `json:"origin_pools"`
				AdvancedOptions *struct {
					AppFirewall *struct {
						Name string `json:"name"`
					} `json:"app_firewall,omitempty"`
					InheritedWAF *struct{} `json:"inherited_waf,omitempty"`
				} `json:"advanced_options,omitempty"`
			} `json:"simple_route,omitempty"`
			RedirectRoute *struct {
				Path struct {
					Prefix string `json:"prefix"`
				} `json:"path"`
				Headers []struct {
					Name  string `json:"name"`
					Regex string `json:"regex,omitempty"`
				} `json:"headers,omitempty"`
				RouteRedirect struct {
					HostRedirect string `json:"host_redirect"`
					PathRedirect string `json:"path_redirect"`
				} `json:"route_redirect"`
			} `json:"redirect_route,omitempty"`
		} `json:"routes"`
		Domains []string `json:"domains"`

		// New Fields for Load Balancer Type
		AdvertiseOnPublicDefaultVIP map[string]interface{} `json:"advertise_on_public_default_vip,omitempty"`
		AdvertiseOnPublic           map[string]interface{} `json:"advertise_on_public,omitempty"`
		AdvertiseOnCustom           map[string]interface{} `json:"advertise_on_custom,omitempty"`
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
	// Determine Load Balancer Type
	loadBalancerLabel := "Load Balancer"
	if apiResponse.Spec.AdvertiseOnPublicDefaultVIP != nil || apiResponse.Spec.AdvertiseOnPublic != nil {
		loadBalancerLabel = "Public Load Balancer"
	} else if apiResponse.Spec.AdvertiseOnCustom != nil {
		loadBalancerLabel = "Private Load Balancer"
	}

	wafName := apiResponse.Spec.AppFirewall.Name
	if wafName == "" {
		wafName = "WAF Not Configured"
	}

	var sb strings.Builder
	wafAdded := make(map[string]bool)
	poolToUpstream := make(map[string]string)

	sb.WriteString("\nMermaid Diagram:\n```mermaid\n")
	sb.WriteString("---\n")
	sb.WriteString("title: F5 Distributed Cloud Load Balancer Service Flow\n")
	sb.WriteString("---\n")
	sb.WriteString("graph LR;\n")
	sb.WriteString("    User -->|SNI| LoadBalancer;\n")
	sb.WriteString(fmt.Sprintf("    LoadBalancer[\"**%s**\"];\n", loadBalancerLabel))

	// Display domains connected to Load Balancer
	for _, domain := range apiResponse.Spec.Domains {
		sb.WriteString(fmt.Sprintf("    LoadBalancer --> %s;\n", domain))
		sb.WriteString(fmt.Sprintf("    %s --> ServicePolicies;\n", domain))
	}

	// Add Service Policy Information Box
	sb.WriteString("    subgraph ServicePolicyInfo [\" \"]\n")
	sb.WriteString("        direction TB\n")
	sb.WriteString("        info_ServicePolicies[\"**Service Policies Info**\"];\n")
	for _, policy := range apiResponse.Spec.ActiveServicePolicies.Policies {
		sb.WriteString(fmt.Sprintf("        info_ServicePolicies[\"**Service Policies Info**<br> - %s\"];\n", policy.Name))
	}
	sb.WriteString("    end\n")
	sb.WriteString("    ServicePolicies --> info_ServicePolicies;\n")

	// Define WAF node
	wafNode := fmt.Sprintf("waf_%s[\"WAF: %s\"]", wafName, wafName)
	sb.WriteString(fmt.Sprintf("    ServicePolicies -->|Process WAF| %s;\n", wafNode))
	sb.WriteString(fmt.Sprintf("    %s --> Routes;\n", wafNode))
	sb.WriteString("    Routes[\"**Routes**\"];\n")

	// Add Default Route Node
	sb.WriteString("    DefaultRoute[\"**Default Route**\"];\n")
	sb.WriteString("    Routes --> DefaultRoute;\n")
	for _, pool := range apiResponse.Spec.DefaultRoutePools {
		poolID := fmt.Sprintf("pool_%s[\"**Pool**<br> %s\"]", pool.Pool.Name, pool.Pool.Name)
		sb.WriteString(fmt.Sprintf("    DefaultRoute --> %s;\n", poolID))
		if _, exists := poolToUpstream[pool.Pool.Name]; !exists {
			origins, err := queryOriginPool(apiURL, token, namespace, pool.Pool.Name, debug)
			if err == nil && len(origins) > 0 {
				upstream := origins[0]
				sb.WriteString(fmt.Sprintf("    %s --> %s;\n", poolID, upstream))
				poolToUpstream[pool.Pool.Name] = upstream
			}
		}
	}

	// Process Routes
	for i, route := range apiResponse.Spec.Routes {
		var matchConditions []string
		var routeWAF string

		if route.SimpleRoute != nil {
			// Process SimpleRoute
			matchConditions = append(matchConditions, "**Route**")
			if route.SimpleRoute.Path.Prefix != "" {
				matchConditions = append(matchConditions, fmt.Sprintf("Path: %s", route.SimpleRoute.Path.Prefix))
			} else if route.SimpleRoute.Path.Regex != "" {
				matchConditions = append(matchConditions, fmt.Sprintf("Regex: %s", route.SimpleRoute.Path.Regex))
			}
			for _, header := range route.SimpleRoute.Headers {
				if header.Regex != "" {
					matchConditions = append(matchConditions, fmt.Sprintf("Header: %s ~ %s", header.Name, header.Regex))
				} else {
					matchConditions = append(matchConditions, fmt.Sprintf("Header: %s", header.Name))
				}
			}
			if route.SimpleRoute.AdvancedOptions != nil && route.SimpleRoute.AdvancedOptions.AppFirewall != nil {
				routeWAF = route.SimpleRoute.AdvancedOptions.AppFirewall.Name
			}

			// Add Route Node
			matchLabel := strings.Join(matchConditions, " <BR> ")
			nodeID := fmt.Sprintf("route_%d", i)
			sb.WriteString(fmt.Sprintf("    %s[\"%s\"];\n", nodeID, matchLabel))
			sb.WriteString(fmt.Sprintf("    Routes --> %s;\n", nodeID))

			// Handle WAF connections
			if routeWAF != "" {
				wafNodeID := fmt.Sprintf("waf_%s", routeWAF)
				if !wafAdded[wafNodeID] {
					sb.WriteString(fmt.Sprintf("    %s[\"**WAF**: %s\"];\n", wafNodeID, routeWAF))
					wafAdded[wafNodeID] = true
				}
				sb.WriteString(fmt.Sprintf("    %s --> %s;\n", nodeID, wafNodeID))

				// Connect WAF to Origin Pools
				for _, pool := range route.SimpleRoute.OriginPools {
					poolID := fmt.Sprintf("pool_%s[\"**Pool**<br> %s\"]", pool.Pool.Name, pool.Pool.Name)
					sb.WriteString(fmt.Sprintf("    %s --> %s;\n", wafNodeID, poolID))
					if _, exists := poolToUpstream[pool.Pool.Name]; !exists {
						origins, err := queryOriginPool(apiURL, token, namespace, pool.Pool.Name, debug)
						if err == nil && len(origins) > 0 {
							upstream := origins[0]
							sb.WriteString(fmt.Sprintf("    %s --> %s;\n", poolID, upstream))
							poolToUpstream[pool.Pool.Name] = upstream
						}
					}
				}
			} else {
				// Directly connect to Origin Pools
				for _, pool := range route.SimpleRoute.OriginPools {
					poolID := fmt.Sprintf("pool_%s[\"**Pool**<br> %s\"]", pool.Pool.Name, pool.Pool.Name)
					sb.WriteString(fmt.Sprintf("    %s --> %s;\n", nodeID, poolID))
					if _, exists := poolToUpstream[pool.Pool.Name]; !exists {
						origins, err := queryOriginPool(apiURL, token, namespace, pool.Pool.Name, debug)
						if err == nil && len(origins) > 0 {
							upstream := origins[0]
							sb.WriteString(fmt.Sprintf("    %s --> %s;\n", poolID, upstream))
							poolToUpstream[pool.Pool.Name] = upstream
						}
					}
				}
			}
		}

		// Process RedirectRoute
		if route.RedirectRoute != nil {
			redirectID := fmt.Sprintf("redirect_%d", i)
			redirectLabel := fmt.Sprintf("Redirect: %s --> %s", route.RedirectRoute.RouteRedirect.HostRedirect, route.RedirectRoute.RouteRedirect.PathRedirect)
			sb.WriteString(fmt.Sprintf("    %s[\"%s\"];\n", redirectID, redirectLabel))
			sb.WriteString(fmt.Sprintf("    Routes --> %s;\n", redirectID))
		}
	}

	sb.WriteString("```\n")
	fmt.Println(sb.String()) // Print final Mermaid output
}
