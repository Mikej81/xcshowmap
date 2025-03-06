package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// APIResponse represents the JSON structure of the Load Balancer API response
// type APIResponse struct {
// 	Spec struct {
// 		AppFirewall struct {
// 			Name string `json:"name"`
// 		} `json:"app_firewall"`
// 		DefaultRoutePools []struct {
// 			Pool struct {
// 				Name string `json:"name"`
// 			} `json:"pool"`
// 		} `json:"default_route_pools"`
// 		ActiveServicePolicies struct {
// 			Policies []struct {
// 				Namespace string `json:"namespace"`
// 				Name      string `json:"name"`
// 			} `json:"policies"`
// 		} `json:"active_service_policies"`
// 		Routes []struct {
// 			SimpleRoute *struct {
// 				Path struct {
// 					Prefix string `json:"prefix"`
// 					Regex  string `json:"regex"`
// 				} `json:"path"`
// 				Headers []struct {
// 					Name  string `json:"name"`
// 					Regex string `json:"regex,omitempty"`
// 				} `json:"headers,omitempty"`
// 				OriginPools []struct {
// 					Pool struct {
// 						Name string `json:"name"`
// 					} `json:"pool"`
// 				} `json:"origin_pools"`
// 				AdvancedOptions *struct {
// 					AppFirewall *struct {
// 						Name string `json:"name"`
// 					} `json:"app_firewall,omitempty"`
// 					InheritedWAF *struct{} `json:"inherited_waf,omitempty"`
// 				} `json:"advanced_options,omitempty"`
// 			} `json:"simple_route,omitempty"`
// 			RedirectRoute *struct {
// 				Path struct {
// 					Prefix string `json:"prefix"`
// 				} `json:"path"`
// 				Headers []struct {
// 					Name  string `json:"name"`
// 					Regex string `json:"regex,omitempty"`
// 				} `json:"headers,omitempty"`
// 				RouteRedirect struct {
// 					HostRedirect string `json:"host_redirect"`
// 					PathRedirect string `json:"path_redirect"`
// 				} `json:"route_redirect"`
// 			} `json:"redirect_route,omitempty"`
// 		} `json:"routes"`
// 		Domains []string `json:"domains"`

// 		APIProtection map[string]interface{} `json:"api_protection_rules,omitempty"`

// 		DisabledBotDefense map[string]interface{} `json:"disable_bot_defense,omitempty"`
// 		EnabledBotDefense  map[string]interface{} `json:"bot_defense,omitempty"`

// 		AdvertiseOnPublicDefaultVIP map[string]interface{} `json:"advertise_on_public_default_vip,omitempty"`
// 		AdvertiseOnPublic           map[string]interface{} `json:"advertise_on_public,omitempty"`
// 		AdvertiseOnCustom           map[string]interface{} `json:"advertise_on_custom,omitempty"`
// 	} `json:"spec"`
// }

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

		APIProtection map[string]interface{} `json:"api_protection_rules,omitempty"`

		DisabledBotDefense map[string]interface{} `json:"disable_bot_defense,omitempty"`
		EnabledBotDefense  map[string]interface{} `json:"bot_defense,omitempty"`

		AdvertiseOnPublicDefaultVIP map[string]interface{} `json:"advertise_on_public_default_vip,omitempty"`
		AdvertiseOnPublic           map[string]interface{} `json:"advertise_on_public,omitempty"`
		AdvertiseOnCustom           map[string]interface{} `json:"advertise_on_custom,omitempty"`

		// New Fields
		CertExpirationTimestamps []string `json:"downstream_tls_certificate_expiration_timestamps"`
		CertState                string   `json:"cert_state"`
	} `json:"spec"`
}

// OriginPoolResponse represents the API response structure for querying an origin pool
type OriginPoolResponse struct {
	Spec struct {
		OriginServers []struct {
			PrivateIP struct {
				IP          string `json:"ip"`
				SiteLocator struct {
					Site struct {
						Name string `json:"name"`
					} `json:"site"`
				} `json:"site_locator"`
			} `json:"private_ip,omitempty"`

			PublicIP struct {
				IP string `json:"ip"`
			} `json:"public_ip,omitempty"`

			PublicName struct {
				DNSName string `json:"dns_name"`
			} `json:"public_name,omitempty"`
		} `json:"origin_servers"`
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
				PrivateIP struct {
					IP          string `json:"ip"`
					SiteLocator struct {
						Site struct {
							Name string `json:"name"`
						} `json:"site"`
					} `json:"site_locator,omitempty"`
				} `json:"private_ip,omitempty"`
				PublicIP struct {
					IP string `json:"ip"`
				} `json:"public_ip,omitempty"`
				PublicName struct {
					DNSName string `json:"dns_name"`
				} `json:"public_name,omitempty"`
			} `json:"origin_servers"`
		} `json:"spec"`
	}

	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, err
	}

	var origins []string
	for _, server := range response.Spec.OriginServers {
		var originLabel string

		// Prefer Private IP with Site Name
		if server.PrivateIP.IP != "" {
			originLabel = server.PrivateIP.IP
			if server.PrivateIP.SiteLocator.Site.Name != "" {
				originLabel += "<br>" + server.PrivateIP.SiteLocator.Site.Name
			}
		} else if server.PublicIP.IP != "" {
			originLabel = server.PublicIP.IP
		} else if server.PublicName.DNSName != "" {
			originLabel = server.PublicName.DNSName
		}

		if originLabel != "" {
			origins = append(origins, fmt.Sprintf("\"%s\"", originLabel)) // Format for Mermaid
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
	nodeCount := 0 // Counter for unique node numbering

	sb.WriteString("\nMermaid Diagram:\n```mermaid\n")
	sb.WriteString("---\n")
	sb.WriteString("title: F5 Distributed Cloud Load Balancer Service Flow\n")
	sb.WriteString("---\n")
	sb.WriteString("graph LR;\n")

	// Start Load Balancer node
	sb.WriteString("    User -->|SNI| LoadBalancer;\n")
	sb.WriteString(fmt.Sprintf("    LoadBalancer[\"**%s**\"];\n", loadBalancerLabel))

	// Define Mermaid style for a green box
	sb.WriteString("    classDef certValid stroke:#01ba44,stroke-width:2px;\n")
	sb.WriteString("    classDef certWarning stroke:#DAA520,stroke-width:2px;\n")
	sb.WriteString("    classDef certError stroke:#B22222,stroke-width:2px;\n")

	// Process Domains with Certificate Info
	for _, domain := range apiResponse.Spec.Domains {
		// Extract Certificate Expiration and State
		certState := "Unknown"
		certClass := "" // Default empty class
		// Set certState based on API response
		if apiResponse.Spec.CertState == "CertificateValid" {
			certState = "Valid"
			certClass = "certValid" // Green box
		} else if apiResponse.Spec.CertState == "CertificateExpiringSoon" {
			certState = "Expiring Soon"
			certClass = "certWarning" // Yellow box
		} else if apiResponse.Spec.CertState == "CertificateExpired" {
			certState = "Expired"
			certClass = "certError" // Red box
		} else if apiResponse.Spec.CertState != "" {
			// Catch-all for other certificate states
			certState = apiResponse.Spec.CertState
			certClass = "certError" // Default error style for unknown states
		}

		certExpiration := "Unknown"
		if len(apiResponse.Spec.CertExpirationTimestamps) > 0 {
			certExpiration = apiResponse.Spec.CertExpirationTimestamps[0] // Use first timestamp
		}

		// Attach certificate details to domain node
		// Format domain node with certificate info
		domainNodeID := strings.ReplaceAll(domain, ".", "_")
		domainNode := fmt.Sprintf("domain_%s[\"%s<br> Cert: %s <br> Exp: %s\"]",
			domainNodeID, domain, certState, certExpiration)

		// Connect domain to Load Balancer
		sb.WriteString(fmt.Sprintf("    LoadBalancer --> %s;\n", domainNode))
		// Connect domain to Service Policies
		sb.WriteString(fmt.Sprintf("    %s --> ServicePolicies;\n", domainNode))

		// Apply the appropriate class for styling
		if certClass != "" {
			sb.WriteString(fmt.Sprintf("    class domain_%s %s;\n", domainNodeID, certClass))
		}
	}

	// Add Service Policies Box
	sb.WriteString("    subgraph ServicePolicies [\"**Service Policies**\"]\n")
	sb.WriteString("        direction TB\n")

	// If no service policies exist, add a "No Service Policies Defined" message
	if len(apiResponse.Spec.ActiveServicePolicies.Policies) == 0 {
		sb.WriteString("        sp_none[\"No Service Policies Defined\"];\n")
	} else {
		// Add each Service Policy as a node under ServicePolicies
		for _, policy := range apiResponse.Spec.ActiveServicePolicies.Policies {
			sb.WriteString(fmt.Sprintf("        sp_%s[\"%s\"];\n", policy.Name, policy.Name))
		}
	}

	sb.WriteString("    end\n")

	// **API Protection Logic**
	apiProtectionNode := ""
	if apiResponse.Spec.APIProtection != nil {
		apiProtectionNode = "api_protection[\"**API Protection Enabled**\"]"
		sb.WriteString(fmt.Sprintf("    ServicePolicies --> %s;\n", apiProtectionNode))
	}

	// **Bot Defense Logic**
	botDefenseNode := ""
	if apiResponse.Spec.EnabledBotDefense != nil {
		botDefenseNode = "bot_defense[\"**Automated Fraud Enabled**\"]"
	} else if apiResponse.Spec.DisabledBotDefense != nil {
		botDefenseNode = "bot_defense[\"**Automated Fraud Disabled**\"]"
	}

	// Link API Protection → Bot Defense (if both exist)
	if apiProtectionNode != "" && botDefenseNode != "" {
		sb.WriteString(fmt.Sprintf("    %s --> %s;\n", apiProtectionNode, botDefenseNode))
	} else if botDefenseNode != "" {
		sb.WriteString(fmt.Sprintf("    ServicePolicies --> %s;\n", botDefenseNode))
	}

	// Define WAF node
	wafNode := fmt.Sprintf("waf_%s[\"WAF: %s\"]", wafName, wafName)

	// Link Bot Defense → WAF
	if botDefenseNode != "" {
		sb.WriteString(fmt.Sprintf("    %s --> %s;\n", botDefenseNode, wafNode))
	} else if apiProtectionNode != "" {
		sb.WriteString(fmt.Sprintf("    %s --> %s;\n", apiProtectionNode, wafNode))
	} else {
		sb.WriteString(fmt.Sprintf("    ServicePolicies -->|Process WAF| %s;\n", wafNode))
	}

	sb.WriteString(fmt.Sprintf("    %s --> Routes;\n", wafNode))
	sb.WriteString("    Routes[\"**Routes**\"];\n")

	// Add Default Route Node
	sb.WriteString("    DefaultRoute[\"**Default Route**\"];\n")
	sb.WriteString("    Routes --> DefaultRoute;\n")
	for _, pool := range apiResponse.Spec.DefaultRoutePools {
		poolID := fmt.Sprintf("pool_%s[\"**Pool**<br>%s\"]", pool.Pool.Name, pool.Pool.Name)
		sb.WriteString(fmt.Sprintf("    DefaultRoute --> %s;\n", poolID))

		if _, exists := poolToUpstream[pool.Pool.Name]; !exists {
			origins, err := queryOriginPool(apiURL, token, namespace, pool.Pool.Name, debug)
			if err == nil && len(origins) > 0 {
				for _, origin := range origins {
					nodeCount++
					originNode := fmt.Sprintf("node_%d[\"%s\"]", nodeCount, origin)
					sb.WriteString(fmt.Sprintf("    %s --> %s;\n", poolID, originNode))
				}
				poolToUpstream[pool.Pool.Name] = origins[0]
			}
		}
	}

	// Process Routes
	for i, route := range apiResponse.Spec.Routes {
		var matchConditions []string
		var routeWAF string

		if route.SimpleRoute != nil {
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
			}

			// Process Origin Pools
			for _, pool := range route.SimpleRoute.OriginPools {
				poolID := fmt.Sprintf("pool_%s[\"**Pool**<br>%s\"]", pool.Pool.Name, pool.Pool.Name)
				if routeWAF != "" {
					// Ensure the WAF connects to the pool instead of the route directly
					wafNodeID := fmt.Sprintf("waf_%s", routeWAF)
					sb.WriteString(fmt.Sprintf("    %s --> %s;\n", wafNodeID, poolID))
				} else {
					// No WAF, so Route connects directly to Pool
					sb.WriteString(fmt.Sprintf("    %s --> %s;\n", nodeID, poolID))
				}

				if _, exists := poolToUpstream[pool.Pool.Name]; !exists {
					origins, err := queryOriginPool(apiURL, token, namespace, pool.Pool.Name, debug)
					if err == nil && len(origins) > 0 {
						for _, origin := range origins {
							nodeCount++
							originNode := fmt.Sprintf("node_%d[\"%s\"]", nodeCount, origin)
							sb.WriteString(fmt.Sprintf("    %s --> %s;\n", poolID, originNode))
						}
						poolToUpstream[pool.Pool.Name] = origins[0]
					}
				}
			}
		}
	}

	sb.WriteString("```\n")
	fmt.Println(sb.String())
}
