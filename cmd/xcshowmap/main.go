package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

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

		ServicePoliciesFromNamespace map[string]interface{} `json:"service_policies_from_namespace,omitempty"`

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

		Domains                     []string               `json:"domains"`
		APIProtection               map[string]interface{} `json:"api_protection_rules,omitempty"`
		DisabledBotDefense          map[string]interface{} `json:"disable_bot_defense,omitempty"`
		EnabledBotDefense           map[string]interface{} `json:"bot_defense,omitempty"`
		AdvertiseOnPublicDefaultVIP map[string]interface{} `json:"advertise_on_public_default_vip,omitempty"`
		AdvertiseOnPublic           map[string]interface{} `json:"advertise_on_public,omitempty"`
		AdvertiseOnCustom           map[string]interface{} `json:"advertise_on_custom,omitempty"`

		AdvertiseCustom struct {
			AdvertiseWhere []struct {
				Site *struct {
					Network string `json:"network"`
					Site    struct {
						Tenant    string `json:"tenant"`
						Namespace string `json:"namespace"`
						Name      string `json:"name"`
						Kind      string `json:"kind,omitempty"`
					} `json:"site"`
					IP   string `json:"ip,omitempty"`
					IPv6 string `json:"ipv6,omitempty"`
				} `json:"site,omitempty"`

				VirtualSite *struct {
					Network     string `json:"network"`
					VirtualSite struct {
						Tenant    string `json:"tenant"`
						Namespace string `json:"namespace"`
						Name      string `json:"name"`
					} `json:"virtual_site"`
				} `json:"virtual_site,omitempty"`

				VirtualSiteWithVIP *struct {
					Network     string `json:"network"`
					VirtualSite struct {
						Tenant    string `json:"tenant"`
						Namespace string `json:"namespace"`
						Name      string `json:"name"`
					} `json:"virtual_site"`
					IP   string `json:"ip,omitempty"`
					IPv6 string `json:"ipv6,omitempty"`
				} `json:"virtual_site_with_vip,omitempty"`

				Vk8sService *struct {
					Site struct {
						Tenant    string `json:"tenant"`
						Namespace string `json:"namespace"`
						Name      string `json:"name"`
						Kind      string `json:"kind,omitempty"`
					} `json:"site"`
				} `json:"vk8s_service,omitempty"`

				UseDefaultPort map[string]interface{} `json:"use_default_port,omitempty"`
			} `json:"advertise_where,omitempty"`
		} `json:"advertise_custom,omitempty"`

		CertExpirationTimestamps []string `json:"downstream_tls_certificate_expiration_timestamps"`
		CertState                string   `json:"cert_state"`

		EnableChallenge      map[string]interface{}   `json:"enable_challenge,omitempty"`
		MoreOption           map[string]interface{}   `json:"more_option,omitempty"`
		UserIdentification   map[string]interface{}   `json:"user_identification,omitempty"`
		DataGuardRules       []map[string]interface{} `json:"data_guard_rules,omitempty"`
		ClientSideDefense    map[string]interface{}   `json:"client_side_defense,omitempty"`
		APISpecification     map[string]interface{}   `json:"api_specification,omitempty"`
		DisableRateLimit     map[string]interface{}   `json:"disable_rate_limit,omitempty"`
		DisableThreatMesh    map[string]interface{}   `json:"disable_threat_mesh,omitempty"`
		DisableMalware       map[string]interface{}   `json:"disable_malware_protection,omitempty"`
		SlowDDoS             map[string]interface{}   `json:"slow_ddos_mitigation,omitempty"`
		L7DDoSActionDefault  map[string]interface{}   `json:"l7_ddos_action_default,omitempty"`
		NoServicePolicies    map[string]interface{}   `json:"no_service_policies,omitempty"`
		SourceIPStickiness   map[string]interface{}   `json:"source_ip_stickiness,omitempty"`
		DisableTrustHeaders  map[string]interface{}   `json:"disable_trust_client_ip_headers,omitempty"`
		EnableMaliciousUsers map[string]interface{}   `json:"enable_malicious_user_detection,omitempty"`
		EnableAPIDiscovery   map[string]interface{}   `json:"enable_api_discovery,omitempty"`
		DefaultSensitiveData map[string]interface{}   `json:"default_sensitive_data_policy,omitempty"`
		GraphQLRules         []map[string]interface{} `json:"graphql_rules,omitempty"`
		ProtectedCookies     []map[string]interface{} `json:"protected_cookies,omitempty"`
		DNSInfo              []map[string]interface{} `json:"dns_info,omitempty"`
		AutoCertInfo         map[string]interface{}   `json:"auto_cert_info,omitempty"`
		InternetVIPInfo      []map[string]interface{} `json:"internet_vip_info,omitempty"`
		State                string                   `json:"state,omitempty"`
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
						Name      string `json:"name"`
						Tenant    string `json:"tenant,omitempty"`
						Namespace string `json:"namespace,omitempty"`
						Kind      string `json:"kind,omitempty"`
					} `json:"site"`
				} `json:"site_locator"`
				InsideNetwork  map[string]interface{} `json:"inside_network,omitempty"`
				OutsideNetwork map[string]interface{} `json:"outside_network,omitempty"`
			} `json:"private_ip,omitempty"`

			PublicIP struct {
				IP string `json:"ip"`
			} `json:"public_ip,omitempty"`

			PublicName struct {
				DNSName         string `json:"dns_name"`
				RefreshInterval int    `json:"refresh_interval,omitempty"`
			} `json:"public_name,omitempty"`

			PrivateName struct {
				DNSName         string `json:"dns_name"`
				RefreshInterval int    `json:"refresh_interval,omitempty"`
				SiteLocator     struct {
					Site struct {
						Name      string `json:"name"`
						Tenant    string `json:"tenant,omitempty"`
						Namespace string `json:"namespace,omitempty"`
						Kind      string `json:"kind,omitempty"`
					} `json:"site"`
				} `json:"site_locator,omitempty"`
				InsideNetwork  map[string]interface{} `json:"inside_network,omitempty"`
				OutsideNetwork map[string]interface{} `json:"outside_network,omitempty"`
			} `json:"private_name,omitempty"`

			K8sService struct {
				ServiceName string `json:"service_name"`
				SiteLocator struct {
					Site struct {
						Name      string `json:"name"`
						Tenant    string `json:"tenant,omitempty"`
						Namespace string `json:"namespace,omitempty"`
						Kind      string `json:"kind,omitempty"`
					} `json:"site"`
				} `json:"site_locator,omitempty"`
				Vk8sNetworks map[string]interface{} `json:"vk8s_networks,omitempty"`
			} `json:"k8s_service,omitempty"`

			Labels map[string]interface{} `json:"labels,omitempty"`
		} `json:"origin_servers"`

		Healthcheck []struct {
			Tenant    string `json:"tenant"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			Kind      string `json:"kind"`
		} `json:"healthcheck,omitempty"`

		Port               int                    `json:"port,omitempty"`
		SameAsEndpointPort map[string]interface{} `json:"same_as_endpoint_port,omitempty"`
		NoTLS              map[string]interface{} `json:"no_tls,omitempty"`
		LoadBalancerAlgo   string                 `json:"loadbalancer_algorithm,omitempty"`
		EndpointSelection  string                 `json:"endpoint_selection,omitempty"`
		AdvancedOptions    map[string]interface{} `json:"advanced_options,omitempty"`
	} `json:"spec"`
}

// LoadBalancerList represents the API response structure for the list of load balancers
type LoadBalancerList struct {
	Items []struct {
		Name           string            `json:"name"`
		Tenant         string            `json:"tenant"`
		Namespace      string            `json:"namespace"`
		Uid            string            `json:"uid"`
		Description    string            `json:"description"`
		Disabled       bool              `json:"disabled"`
		OwnerView      *string           `json:"owner_view"`
		Metadata       *string           `json:"metadata"`
		SystemMetadata *string           `json:"system_metadata"`
		GetSpec        *string           `json:"get_spec"`
		StatusSet      []interface{}     `json:"status_set"`
		Labels         map[string]string `json:"labels"`
		Annotations    map[string]string `json:"annotations"`
	} `json:"items"`
}

// NamespaceList represents the API response structure for the list of namespaces
type NamespaceList struct {
	Items []struct {
		Name           string            `json:"name"`
		Namespace      string            `json:"namespace_list,omitempty"`
		Tenant         string            `json:"tenant"`
		Uid            string            `json:"uid"`
		Labels         map[string]string `json:"labels"`
		Annotations    map[string]string `json:"annotations"`
		Description    string            `json:"description"`
		Disabled       bool              `json:"disabled"`
		OwnerView      *string           `json:"owner_view,omitempty"`
		Metadata       *string           `json:"metadata,omitempty"`
		SystemMetadata *string           `json:"system_metadata,omitempty"`
		GetSpec        *string           `json:"get_spec,omitempty"`
		StatusSet      []interface{}     `json:"status_set,omitempty"`
	} `json:"items"`
}

var httpClient = &http.Client{}

func main() {
	// Define CLI arguments
	apiURL := flag.String("api-url", "", "Base API URL")
	token := flag.String("token", "", "API token for authentication")
	namespace := flag.String("namespace", "", "Namespace to query")
	loadBalancer := flag.String("load-balancer", "", "Load balancer to inspect")
	debug := flag.Bool("debug", false, "Enable debug mode to print raw API response")
	batch := flag.Bool("batch", false, "Batch mode to process multiple load balancers")

	flag.Parse()

	// Validate required arguments
	if *apiURL == "" || *token == "" || *namespace == "" || *loadBalancer == "" {
		fmt.Println("Usage: xcshowmap -api-url <API_URL> -token <TOKEN> -namespace <NAMESPACE> -load-balancer <LB> [-debug]")
		os.Exit(1)
	}
	var err error
	var nslist []string
	var lblist []string
	if *namespace == "all" {
		nslist, err = queryNamespaces(*apiURL, *token, *debug)
		if err != nil {
			fmt.Printf("Error querying namespaces: %v\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("\n--- Namespace list (Debug Mode) ---\n")
			fmt.Printf("Debug: nslist length = %d, contents = %v\n", len(nslist), nslist)
		}
	} else {
		nslist = []string{*namespace}
	}
	// Loop through each namespace and query load balancers
	for _, ns := range nslist {
		if *loadBalancer == "all" {
			lblist, err = queryNSLoadBalancers(*apiURL, *token, ns, *debug)
			if err != nil {
				fmt.Printf("Error querying load balancers: %v\n", err)
				os.Exit(1)
			}
			if *debug {
				fmt.Printf("\n--- Load balancer list (Debug Mode) ---\n")
				fmt.Printf("Debug: lblist length = %d, contents = %v\n", len(lblist), lblist)
			}
		} else {
			lblist = []string{*loadBalancer}
		}
		// For each HTTP Load Balancer, process and create a diagram
		for _, lb := range lblist {
			if *debug {
				fmt.Printf("\n--- Getting details of load balancer '%s' (Debug Mode) ---\n", lb)
			}
			// Construct API URL
			queryURL := fmt.Sprintf("%s/api/config/namespaces/%s/http_loadbalancers/%s", *apiURL, ns, lb)

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
			var mermaid strings.Builder
			directory := fmt.Sprintf("./%s", ns)
			if _, err := os.Stat(directory); os.IsNotExist(err) {
				if err := os.Mkdir(directory, 0755); err != nil {
					fmt.Printf("Error creating directory '%s': %v\n", directory, err)
					os.Exit(1)
				}
			}
			filename := fmt.Sprintf("%s/%s.mmd", directory, lb)

			mermaid = generateMermaidDiagram(apiResponse, *apiURL, *token, ns, *debug, lb, *batch)
			if *batch {
				f, err := os.Create(filename)
				if err != nil {
					fmt.Printf("Error creating file '%s': %v\n", filename, err)
					os.Exit(1)
				}
				if _, err := f.WriteString(mermaid.String()); err != nil {
					fmt.Printf("Error writing to file: %v\n", err)
					f.Close()
					os.Exit(1)
				}

				defer f.Close()
			}
		}
	}
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

	return io.ReadAll(resp.Body)
}

// queryNameSpaces fetches the list of all namespaces you are permissioned to
func queryNamespaces(apiURL string, token string, debug bool) ([]string, error) {
	queryURL := fmt.Sprintf("%s/api/web/namespaces", apiURL)

	data, err := queryAPI(queryURL, token)
	if err != nil {
		return nil, err
	}

	// Debug mode: Print raw Origin Pool API response
	if debug {
		fmt.Printf("\n--- Namespace list (Debug Mode) ---\n")
		fmt.Println(string(data))
		fmt.Println("---------------------------------------------------")
	}
	var response NamespaceList
	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, err
	}

	var nslist []string
	for _, name := range response.Items {
		nslist = append(nslist, name.Name)
	}

	return nslist, nil
}

// queryNSLoadBalancers fetches the list of all HTTP Loadbalancers from an namespace
func queryNSLoadBalancers(apiURL string, token string, namespace string, debug bool) ([]string, error) {
	queryURL := fmt.Sprintf("%s/api/config/namespaces/%s/http_loadbalancers", apiURL, namespace)

	data, err := queryAPI(queryURL, token)
	if err != nil {
		return nil, err
	}

	// Debug mode: Print raw Origin Pool API response
	if debug {
		fmt.Printf("\n--- Load balancer list (Debug Mode) ---\n")
		fmt.Println(string(data))
		fmt.Println("---------------------------------------------------")
	}
	var response LoadBalancerList
	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, err
	}

	var httplb []string
	for _, server := range response.Items {
		httplb = append(httplb, server.Name)
	}

	return httplb, nil
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

	var response OriginPoolResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, err
	}

	var origins []string
	for _, server := range response.Spec.OriginServers {
		var originLabel string

		switch {
		case server.PrivateIP.IP != "":
			originLabel = fmt.Sprintf("Private IP: %s", server.PrivateIP.IP)
			if site := server.PrivateIP.SiteLocator.Site.Name; site != "" {
				originLabel += "<br> Upstream Site: " + site
			}
		case server.PublicIP.IP != "":
			originLabel = fmt.Sprintf("Public IP: %s", server.PublicIP.IP)
		case server.PublicName.DNSName != "":
			originLabel = fmt.Sprintf("Public DNS: %s", server.PublicName.DNSName)
		case server.PrivateName.DNSName != "":
			originLabel = fmt.Sprintf("Private DNS: %s", server.PrivateName.DNSName)
			if site := server.PrivateName.SiteLocator.Site.Name; site != "" {
				originLabel += "<br> Upstream Site: " + site
			}
		case server.K8sService.ServiceName != "":
			originLabel = fmt.Sprintf("K8s Service: %s", server.K8sService.ServiceName)
			if site := server.K8sService.SiteLocator.Site.Name; site != "" {
				originLabel += "<br> Upstream Site: " + site
			}
		}

		if originLabel != "" {
			// Prevent auto-linking in Mermaid by escaping periods
			safeOrigin := strings.ReplaceAll(originLabel, ".", "#46;")
			origins = append(origins, safeOrigin)
		}
	}

	return origins, nil
}

// generateMermaidDiagram outputs a Mermaid diagram from API data
func generateMermaidDiagram(apiResponse APIResponse, apiURL, token, namespace string, debug bool, loadbalancer string, batch bool) strings.Builder {
	// Determine Load Balancer Type
	loadBalancerLabel := "Load Balancer"

	// Determine type
	if apiResponse.Spec.AdvertiseOnPublicDefaultVIP != nil ||
		apiResponse.Spec.AdvertiseOnPublic != nil ||
		(apiResponse.Spec.AdvertiseOnPublicDefaultVIP != nil && len(apiResponse.Spec.AdvertiseOnPublicDefaultVIP) == 0) {
		loadBalancerLabel = "Public Load Balancer"
	} else if len(apiResponse.Spec.AdvertiseOnCustom) > 0 || len(apiResponse.Spec.AdvertiseCustom.AdvertiseWhere) > 0 {
		loadBalancerLabel = "Private Load Balancer"
	}

	wafName := apiResponse.Spec.AppFirewall.Name
	wafClass := "certValid" // Default to valid
	if wafName == "" {
		wafName = "WAF Not Configured"
		if loadBalancerLabel == "Public Load Balancer" {
			wafClass = "noWaf" // It is not great to have no WAF
		} else {
			wafClass = "certError" // Private LB without WAF is ok but quesrtionable
		}
	}

	var sb strings.Builder
	wafAdded := make(map[string]bool)
	poolToUpstream := make(map[string]string)
	nodeCount := 0

	if !batch {
		sb.WriteString("\nMermaid Diagram:\n")
		sb.WriteString("```mermaid\n")
	}
	sb.WriteString("---\n")
	sb.WriteString(fmt.Sprintf("title: %s Load Balancer Service Flow\n", loadbalancer))
	sb.WriteString("---\n")
	sb.WriteString("graph TD;\n")

	// Load Balancer with cert info
	sb.WriteString("    User --> LoadBalancer;\n")
	// sb.WriteString("    LoadBalancer --> SNI;\n")
	// sb.WriteString("    SNI[\"**SNI**\"];\n")

	sb.WriteString(fmt.Sprintf("    LoadBalancer[\"**%s %s**\"];\n", loadbalancer, loadBalancerLabel))

	// Define Mermaid style for a green box
	sb.WriteString("    classDef certValid stroke:#01ba44,stroke-width:2px;\n")
	sb.WriteString("    classDef certWarning stroke:#DAA520,stroke-width:2px;\n")
	sb.WriteString("    classDef certError stroke:#B22222,stroke-width:2px;\n")
	sb.WriteString("    classDef noWaf fill:#FF5733,stroke:#B22222,stroke-width:2px;\n")
	sb.WriteString("    classDef animate stroke-dasharray: 9,5,stroke-dashoffset: 900,animation: dash 25s linear infinite;\n")
	edges := 0
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
		domainNodeID := strings.ReplaceAll(domain, ".", "_")
		domainNode := fmt.Sprintf("domain_%s[\"%s<br> Cert: %s <br> Exp: %s\"]",
			domainNodeID, domain, certState, certExpiration)

		//sb.WriteString(fmt.Sprintf("    SNI --> %s;\n", domainNode))
		sb.WriteString(fmt.Sprintf("    LoadBalancer e%d@-- SNI --> %s;\n", edges, domainNode))
		edges++
		// Apply the appropriate class for styling
		if certClass != "" {
			sb.WriteString(fmt.Sprintf("    class domain_%s %s;\n", domainNodeID, certClass))
		}
	}

	if loadBalancerLabel != "Private Load Balancer" {
		for _, domain := range apiResponse.Spec.Domains {
			domainNodeID := strings.ReplaceAll(domain, ".", "_")
			sb.WriteString(fmt.Sprintf("    domain_%s e%d@--> ServicePolicies;\n", domainNodeID, edges))
		}
	}

	if loadBalancerLabel == "Private Load Balancer" && len(apiResponse.Spec.AdvertiseCustom.AdvertiseWhere) > 0 {
		// Declare only the nodes inside the subgraph
		sb.WriteString("    subgraph AdvertiseTargets [\"**Advertised To**\"]\n")
		sb.WriteString("        direction LR\n")

		for i, adv := range apiResponse.Spec.AdvertiseCustom.AdvertiseWhere {
			nodeID := fmt.Sprintf("adv_target_%d", i)
			label := ""

			if adv.Site != nil {
				label = fmt.Sprintf("Site: %s<br>Network: %s", adv.Site.Site.Name, adv.Site.Network)
				if adv.Site.IP != "" {
					label += fmt.Sprintf("<br>IP: %s", adv.Site.IP)
				}
			} else if adv.VirtualSite != nil {
				label = fmt.Sprintf("Virtual Site: %s<br>Network: %s",
					adv.VirtualSite.VirtualSite.Name, adv.VirtualSite.Network)
			} else if adv.VirtualSiteWithVIP != nil {
				label = fmt.Sprintf("Virtual Site: %s<br>Network: %s",
					adv.VirtualSiteWithVIP.VirtualSite.Name, adv.VirtualSiteWithVIP.Network)
				if adv.VirtualSiteWithVIP.IP != "" {
					label += fmt.Sprintf("<br>IP: %s", adv.VirtualSiteWithVIP.IP)
				}
			} else if adv.Vk8sService != nil {
				label = fmt.Sprintf("vK8s Service on  <br/> %s", adv.Vk8sService.Site.Name)
			} else {
				label = "Unknown Advertise Target"
			}

			sb.WriteString(fmt.Sprintf("        %s[\"%s\"];\n", nodeID, label))
		}

		sb.WriteString("    end\n")

		// Now do the arrows OUTSIDE the subgraph
		for i := range apiResponse.Spec.AdvertiseCustom.AdvertiseWhere {
			nodeID := fmt.Sprintf("adv_target_%d", i)
			for _, domain := range apiResponse.Spec.Domains {
				domainNodeID := strings.ReplaceAll(domain, ".", "_")
				sb.WriteString(fmt.Sprintf("    domain_%s e%d@--> %s;\n", domainNodeID, edges, nodeID))
				edges++
			}
			sb.WriteString(fmt.Sprintf("    %s e%d@--> ServicePolicies;\n", nodeID, edges))
			edges++
		}
	}

	// Add Common Security Controls Box
	sb.WriteString("    subgraph ServicePolicies [\"**Common Security Controls**\"]\n")
	sb.WriteString("        direction LR\n")

	// Add Service Policies
	if len(apiResponse.Spec.ActiveServicePolicies.Policies) > 0 {
		for _, policy := range apiResponse.Spec.ActiveServicePolicies.Policies {
			sb.WriteString(fmt.Sprintf("        sp_%s[\"%s\"];\n", policy.Name, policy.Name))
		}
	} else if apiResponse.Spec.ServicePoliciesFromNamespace != nil {
		sb.WriteString("        sp_ns[\"Apply Namespace Service Policies\"];\n")
	} else {
		sb.WriteString("        sp_none[\"No Service Policies Defined\"];\n")
	}

	// Add Malicious User Detection if enabled
	if apiResponse.Spec.EnableMaliciousUsers != nil {
		sb.WriteString("        mud[\"Malicious User Detection\"];\n")
	}

	sb.WriteString("    end\n")

	// **API Protection Logic**
	apiProtectionNode := ""
	if apiResponse.Spec.APIProtection != nil {
		apiProtectionNode = "api_protection[\"**API Protection Enabled**\"]"
		sb.WriteString(fmt.Sprintf("    ServicePolicies e%d@--> %s;\n", edges, apiProtectionNode))
		edges++
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
		sb.WriteString(fmt.Sprintf("    %s e%d@--> %s;\n", apiProtectionNode, edges, botDefenseNode))
		edges++
	} else if botDefenseNode != "" {
		sb.WriteString(fmt.Sprintf("    ServicePolicies e%d@--> %s;\n", edges, botDefenseNode))
		edges++
	}

	// Define WAF node
	wafNodeID := strings.ReplaceAll(wafName, " ", "_")
	wafNode := fmt.Sprintf("waf_%s[\"WAF: %s\"]", wafNodeID, wafName)

	// Link Bot Defense → WAF
	if botDefenseNode != "" {
		sb.WriteString(fmt.Sprintf("    %s e%d@--> %s;\n", botDefenseNode, edges, wafNode))
		edges++
	} else if apiProtectionNode != "" {
		sb.WriteString(fmt.Sprintf("    %se%d@ --> %s;\n", apiProtectionNode, edges, wafNode))
		edges++
	} else {
		sb.WriteString(fmt.Sprintf("    ServicePolicies e%d@-->|Process WAF| %s;\n", edges, wafNode))
		edges++
	}
	sb.WriteString(fmt.Sprintf("    class waf_%s %s;\n", wafNodeID, wafClass))
	sb.WriteString(fmt.Sprintf("    %s e%d@--> Routes;\n", wafNode, edges))
	edges++
	sb.WriteString("    Routes[\"**Routes**\"];\n")

	// Add Default Route Node
	sb.WriteString("    DefaultRoute[\"**Default Route**\"];\n")
	sb.WriteString(fmt.Sprintf("    Routes e%d@--> DefaultRoute;\n", edges))
	edges++
	for _, pool := range apiResponse.Spec.DefaultRoutePools {
		poolID := fmt.Sprintf("pool_%s[\"**Pool**<br>%s\"]", pool.Pool.Name, pool.Pool.Name)
		sb.WriteString(fmt.Sprintf("    DefaultRoute --> %s;\n", poolID))

		if _, exists := poolToUpstream[pool.Pool.Name]; !exists {
			origins, err := queryOriginPool(apiURL, token, namespace, pool.Pool.Name, debug)
			if err == nil && len(origins) > 0 {
				for _, origin := range origins {
					nodeCount++
					originNode := fmt.Sprintf("node_%d[\"%s\"]", nodeCount, origin)
					sb.WriteString(fmt.Sprintf("    %s e%d@--> %s;\n", poolID, edges, originNode))
					edges++
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
				matchConditions = append(matchConditions, fmt.Sprintf("Path Match: %s", route.SimpleRoute.Path.Prefix))
			} else if route.SimpleRoute.Path.Regex != "" {
				matchConditions = append(matchConditions, fmt.Sprintf("Path Regex: %s", route.SimpleRoute.Path.Regex))
			}
			for _, header := range route.SimpleRoute.Headers {
				if header.Regex != "" {
					matchConditions = append(matchConditions, fmt.Sprintf("Header Regex: %s ~ %s", header.Name, header.Regex))
				} else {
					matchConditions = append(matchConditions, fmt.Sprintf("Header Match: %s", header.Name))
				}
			}
			if route.SimpleRoute.AdvancedOptions != nil && route.SimpleRoute.AdvancedOptions.AppFirewall != nil {
				routeWAF = route.SimpleRoute.AdvancedOptions.AppFirewall.Name
			}

			// Add Route Node
			matchLabel := strings.Join(matchConditions, " <BR> ")
			nodeID := fmt.Sprintf("route_%d", i)
			sb.WriteString(fmt.Sprintf("    %s[\"%s\"];\n", nodeID, matchLabel))
			sb.WriteString(fmt.Sprintf("    Routes e%d@--> %s;\n", edges, nodeID))
			edges++

			// Handle WAF connections
			if routeWAF != "" {
				wafNodeID := fmt.Sprintf("waf_%s", routeWAF)
				if !wafAdded[wafNodeID] {
					sb.WriteString(fmt.Sprintf("    %s[\"**WAF**: %s\"];\n", wafNodeID, routeWAF))
					wafAdded[wafNodeID] = true
				}
				sb.WriteString(fmt.Sprintf("    %s e%d@--> %s;\n", nodeID, edges, wafNodeID))
				edges++
			}

			// Process Origin Pools
			for _, pool := range route.SimpleRoute.OriginPools {
				poolID := fmt.Sprintf("pool_%s[\"**Pool**<br>%s\"]", pool.Pool.Name, pool.Pool.Name)
				if routeWAF != "" {
					// Ensure the WAF connects to the pool instead of the route directly
					wafNodeID := fmt.Sprintf("waf_%s", routeWAF)
					sb.WriteString(fmt.Sprintf("    %s e%d@--> %s;\n", wafNodeID, edges, poolID))
					edges++
				} else {
					// No WAF, so Route connects directly to Pool
					sb.WriteString(fmt.Sprintf("    %s e%d@--> %s;\n", nodeID, edges, poolID))
					edges++
				}

				if _, exists := poolToUpstream[pool.Pool.Name]; !exists {
					origins, err := queryOriginPool(apiURL, token, namespace, pool.Pool.Name, debug)
					originlabel := strings.Builder{}
					if err == nil && len(origins) > 0 {
						for _, origin := range origins {
							nodeCount++
							if *&debug {
								fmt.Printf("\n--- Origin Pool %s (Debug Mode) ---\n", origin)
							}
							originlabel.WriteString(fmt.Sprintf("%s<br>", origin))
						}
						originNode := fmt.Sprintf("node_op_%s@{ shape: processes, label: \"%s\"}", pool.Pool.Name, originlabel.String())
						sb.WriteString(fmt.Sprintf("    %s e%d@--> %s;\n", poolID, edges, originNode))
						edges++
						poolToUpstream[pool.Pool.Name] = origins[0]
					}
				}
			}
		}
	}
	for edge := range edges {
		sb.WriteString(fmt.Sprintf("    class e%d animate\n", edge))
	}
	if !batch {
		sb.WriteString("```\n")
		fmt.Println(sb.String())
	}

	return sb
}
