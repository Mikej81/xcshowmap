package xcshowmap

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// APIResponse represents the JSON structure
type APIResponse struct {
	Spec struct {
		AppFirewall struct {
			Name string `json:"name"`
		} `json:"app_firewall"`
		Domains []string `json:"domains"`
	} `json:"spec"`
}

// QueryAPI makes a GET request
func QueryAPI(url, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "APIToken "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	return ioutil.ReadAll(resp.Body)
}

// GenerateMermaidDiagram creates a Mermaid chart
func GenerateMermaidDiagram(apiResponse APIResponse) string {
	var sb strings.Builder
	sb.WriteString("graph LR;\n")
	sb.WriteString("    User -->|SNI| LoadBalancer;\n")

	for _, domain := range apiResponse.Spec.Domains {
		sb.WriteString(fmt.Sprintf("    LoadBalancer --> %s;\n", domain))
	}

	return sb.String()
}
