package wazuh

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL                   string
	IndexerURL                string
	User, Pass, Token         string
	IndexerUser, IndexerPass  string
	HTTPClient                *http.Client
}

func NewClient(urlStr, indexerStr, user, pass, idxUser, idxPass string) *Client {
	return &Client{
		BaseURL:     strings.TrimRight(urlStr, "/"),
		IndexerURL:  strings.TrimRight(indexerStr, "/"),
		User:        user, 
		Pass:        pass,
		IndexerUser: idxUser,
		IndexerPass: idxPass,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

func (c *Client) Authenticate() error {
	apiURL := fmt.Sprintf("%s/security/user/authenticate?raw=true", c.BaseURL)
	req, _ := http.NewRequest("POST", apiURL, nil)
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.User+":"+c.Pass)))
	
	resp, err := c.HTTPClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 { return fmt.Errorf("auth failed: %d", resp.StatusCode) }
	c.Token = strings.TrimSpace(string(body))
	return nil
}

func (c *Client) VerifyHashInIndexer(agentID, targetHash string) (bool, error) {
	query := map[string]interface{}{
		"size": 1,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []interface{}{
					map[string]interface{}{"term": map[string]string{"agent.id": agentID}},
					map[string]interface{}{"term": map[string]string{"agent.labels.hardware_hash": targetHash}},
				},
			},
		},
	}
	
	bodyBytes, _ := json.Marshal(query)
	searchURL := fmt.Sprintf("%s/wazuh-alerts-*/_search", c.IndexerURL)

	req, _ := http.NewRequest("POST", searchURL, bytes.NewBuffer(bodyBytes))
	req.Header.Add("Content-Type", "application/json")
	
	auth := base64.StdEncoding.EncodeToString([]byte(c.IndexerUser + ":" + c.IndexerPass))
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err := c.HTTPClient.Do(req)
	if err != nil { return false, fmt.Errorf("connection error: %v", err) }
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false, fmt.Errorf("auth failed (user: %s): %d", c.IndexerUser, resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("http error: %d", resp.StatusCode)
	}

	var res struct {
		Hits struct {
			Total struct { Value int `json:"value"` } `json:"total"`
			Hits []interface{} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil { return false, err }

	if res.Hits.Total.Value > 0 || len(res.Hits.Hits) > 0 {
		return true, nil
	}

	return false, nil
}

func (c *Client) GetAgentCandidates(searchQuery string) ([]struct{ ID, Name string }, error) {
	execute := func() ([]struct{ ID, Name string }, error) {
		if c.Token == "" { return nil, fmt.Errorf("unauthorized") }
		baseURL, _ := url.Parse(c.BaseURL + "/agents")
		params := url.Values{}
		params.Add("search", searchQuery)
		params.Add("select", "id,name")
		params.Add("limit", "50")
		baseURL.RawQuery = params.Encode()

		req, _ := http.NewRequest("GET", baseURL.String(), nil)
		req.Header.Add("Authorization", "Bearer "+c.Token)
		resp, err := c.HTTPClient.Do(req)
		if err != nil { return nil, err }
		defer resp.Body.Close()
		if resp.StatusCode == 401 { return nil, fmt.Errorf("unauthorized") }

		var res struct { Data struct { AffectedItems []struct { ID string `json:"id"`; Name string `json:"name"` } `json:"affected_items"` } `json:"data"` }
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil { return nil, err }
		
		candidates := []struct{ ID, Name string }{}
		for _, item := range res.Data.AffectedItems {
			candidates = append(candidates, struct{ ID, Name string }{item.ID, item.Name})
		}
		return candidates, nil
	}
	result, err := execute()
	if err != nil && err.Error() == "unauthorized" { c.Authenticate(); result, err = execute() }
	return result, err
}

func (c *Client) GetAgentLabels(agentID string) (map[string]string, error) {
	if c.Token == "" { c.Authenticate() }
	apiURL := fmt.Sprintf("%s/agents/%s/config/agent/labels", c.BaseURL, agentID)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTPClient.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return nil, fmt.Errorf("http error %d", resp.StatusCode) }
	
	var res struct { Data struct { Labels []struct { Key string `json:"key"`; Value string `json:"value"` } `json:"labels"` } `json:"data"` }
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil { return nil, err }
	labelMap := make(map[string]string)
	for _, l := range res.Data.Labels { labelMap[l.Key] = l.Value }
	return labelMap, nil
}

func (c *Client) GetAgentKey(agentID string) (string, error) {
	if c.Token == "" { c.Authenticate() }
	apiURL := fmt.Sprintf("%s/agents/%s/key", c.BaseURL, agentID)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTPClient.Do(req)
	if err != nil { return "", err }
	defer resp.Body.Close()
	
	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil { return "", err }
	data, ok := raw["data"].(map[string]interface{})
	if !ok { return "", fmt.Errorf("invalid response") }
	if items, ok := data["affected_items"].([]interface{}); ok && len(items) > 0 {
		if item, ok := items[0].(map[string]interface{}); ok {
			if key, ok := item["key"].(string); ok { return key, nil }
		}
	}
	if key, ok := data["key"].(string); ok { return key, nil }
	return "", fmt.Errorf("key not found")
}

func (c *Client) GetAgentByName(agentName string) (string, error) {
	candidates, err := c.GetAgentCandidates(agentName)
	if err != nil { return "", err }
	for _, can := range candidates { if can.Name == agentName { return can.ID, nil } }
	return "", nil
}

// DeleteAgent: FIXED (status=all AND older_than=0s)
func (c *Client) DeleteAgent(agentID string) (string, error) {
	execute := func() (int, string, error) {
		if c.Token == "" { return 401, "", nil }
		
		baseURL, _ := url.Parse(c.BaseURL + "/agents")
		params := url.Values{}
		
		// Parameter Wajib
		params.Add("agents_list", agentID)
		params.Add("status", "all")       // Wajib ada (Fix error 400)
		params.Add("older_than", "0s")    // Wajib ada untuk bypass limit 7 hari (Fix error 1731)
		
		baseURL.RawQuery = params.Encode()

		req, _ := http.NewRequest("DELETE", baseURL.String(), nil)
		req.Header.Add("Authorization", "Bearer "+c.Token)
		
		resp, err := c.HTTPClient.Do(req)
		if err != nil { return 0, "", err }
		defer resp.Body.Close()
		
		bodyBytes, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(bodyBytes), nil
	}

	code, body, err := execute()
	if code == 401 { c.Authenticate(); code, body, err = execute() }
	if err != nil { return "", err }
	if code != 200 { return body, fmt.Errorf("api error %d", code) }
	return body, nil
}