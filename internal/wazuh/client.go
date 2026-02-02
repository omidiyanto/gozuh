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
	"os"
	"strings"
	"time"
	"gozuh/internal/config"
)

// WazuhErrorResponse is used to parse specific API error codes
type WazuhErrorResponse struct {
	Error   int    `json:"error"`
	Message string `json:"message"`
	Data    struct {
		FailedItems []struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
			ID []string `json:"id"`
		} `json:"failed_items"`
	} `json:"data"`
}

type Client struct {
	BaseURL     string
	IndexerURL  string
	User, Pass, Token string
	IndexerUser, IndexerPass string
	HTTPClient  *http.Client
}

type AgentInfo struct {
	Status        string   `json:"status"`
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Group         []string `json:"group"`
	LastKeepAlive string   `json:"lastKeepAlive"`
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
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

func GetLocalAuth() (id string, name string, err error) {
	content, err := os.ReadFile(config.WazuhClientKey)
	if err != nil { return "", "", err }

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			return parts[0], parts[1], nil
		}
	}
	return "", "", fmt.Errorf("empty keys")
}

func (c *Client) Authenticate() error {
	apiURL := fmt.Sprintf("%s/security/user/authenticate?raw=true", c.BaseURL)
	req, _ := http.NewRequest("POST", apiURL, nil)
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.User+":"+c.Pass)))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("auth failed: %d", resp.StatusCode)
	}
	c.Token = strings.TrimSpace(string(body))
	return nil
}

func (c *Client) GetAgentInfo(agentID string) (*AgentInfo, error) {
	if c.Token == "" { c.Authenticate() }
	apiURL := fmt.Sprintf("%s/agents?agents_list=%s&select=status,id,name,group,lastKeepAlive", c.BaseURL, agentID)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		c.Authenticate()
		return c.GetAgentInfo(agentID)
	}

	if resp.StatusCode != 200 { return nil, fmt.Errorf("http_error_%d", resp.StatusCode) }

	var res struct {
		Data struct {
			AffectedItems []AgentInfo `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil { return nil, err }

	if len(res.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("not_found")
	}

	return &res.Data.AffectedItems[0], nil
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
	if err != nil {
		return false, fmt.Errorf("connection error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false, fmt.Errorf("auth failed (user: %s): %d", c.IndexerUser, resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("http error: %d", resp.StatusCode)
	}

	var res struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []interface{} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, err
	}

	if res.Hits.Total.Value > 0 || len(res.Hits.Hits) > 0 {
		return true, nil
	}

	return false, nil
}

func (c *Client) GetAgentCandidates(searchQuery string) ([]AgentInfo, error) {
	execute := func() ([]AgentInfo, error) {
		if c.Token == "" {
			return nil, fmt.Errorf("unauthorized")
		}
		baseURL, _ := url.Parse(c.BaseURL + "/agents")
		params := url.Values{}
		params.Add("search", searchQuery)
		params.Add("select", "id,name,group")
		params.Add("limit", "50")
		baseURL.RawQuery = params.Encode()

		req, _ := http.NewRequest("GET", baseURL.String(), nil)
		req.Header.Add("Authorization", "Bearer "+c.Token)
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == 401 {
			return nil, fmt.Errorf("unauthorized")
		}

		var res struct {
			Data struct {
				AffectedItems []AgentInfo `json:"affected_items"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return nil, err
		}

		return res.Data.AffectedItems, nil
	}
	result, err := execute()
	if err != nil && err.Error() == "unauthorized" {
		c.Authenticate()
		result, err = execute()
	}
	return result, err
}

func (c *Client) GetAgentLabels(agentID string) (map[string]string, error) {
	if c.Token == "" {
		c.Authenticate()
	}
	apiURL := fmt.Sprintf("%s/agents/%s/config/agent/labels", c.BaseURL, agentID)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http error %d", resp.StatusCode)
	}

	var res struct {
		Data struct {
			Labels []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"labels"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	labelMap := make(map[string]string)
	for _, l := range res.Data.Labels {
		labelMap[l.Key] = l.Value
	}
	return labelMap, nil
}

func (c *Client) GetAgentKey(agentID string) (string, error) {
	if c.Token == "" {
		c.Authenticate()
	}
	apiURL := fmt.Sprintf("%s/agents/%s/key", c.BaseURL, agentID)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", err
	}
	data, ok := raw["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response")
	}
	if items, ok := data["affected_items"].([]interface{}); ok && len(items) > 0 {
		if item, ok := items[0].(map[string]interface{}); ok {
			if key, ok := item["key"].(string); ok {
				return key, nil
			}
		}
	}
	if key, ok := data["key"].(string); ok {
		return key, nil
	}
	return "", fmt.Errorf("key not found")
}

func (c *Client) DeleteAgent(agentID string) (string, error) {
	execute := func() (int, string, error) {
		if c.Token == "" {
			return 401, "", nil
		}

		baseURL, _ := url.Parse(c.BaseURL + "/agents")
		params := url.Values{}
		params.Add("agents_list", agentID)
		params.Add("status", "all")
		params.Add("older_than", "0s")
		baseURL.RawQuery = params.Encode()

		req, _ := http.NewRequest("DELETE", baseURL.String(), nil)
		req.Header.Add("Authorization", "Bearer "+c.Token)

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(bodyBytes), nil
	}

	code, body, err := execute()
	if code == 401 {
		c.Authenticate()
		code, body, err = execute()
	}
	if err != nil {
		return "", err
	}
	if code != 200 {
		return body, fmt.Errorf("api error %d", code)
	}
	return body, nil
}

func (c *Client) AssignGroups(agentID string, groups string) error {
	if c.Token == "" {
		if err := c.Authenticate(); err != nil {
			return err
		}
	}
	currentAgent, err := c.GetAgentInfo(agentID)
	if err != nil {
		return fmt.Errorf("failed to fetch current status: %v", err)
	}
	rawList := strings.Split(groups, ",")
	targetMap := make(map[string]bool)
	var targetGroups []string

	for _, g := range rawList {
		if t := strings.TrimSpace(g); t != "" {
			targetGroups = append(targetGroups, t)
			targetMap[strings.ToLower(t)] = true
		}
	}
	if len(targetGroups) == 0 {
		targetGroups = append(targetGroups, "default")
		targetMap["default"] = true
	}
	for _, currGroup := range currentAgent.Group {
		if !targetMap[strings.ToLower(currGroup)] {
			err := c.modifyGroup(agentID, currGroup, "DELETE")
			if err != nil {
				fmt.Printf("      [WARN] Failed to remove old group '%s': %v\n", currGroup, err)
			} else {
				fmt.Printf("      [-] Removed from group: %s\n", currGroup)
			}
		}
	}
	for _, groupID := range targetGroups {
		err := c.modifyGroup(agentID, groupID, "PUT")
		if err != nil {
			return fmt.Errorf("failed to add group %s: %v", groupID, err)
		}
	}
	return nil
}

func (c *Client) modifyGroup(agentID, groupID, method string) error {
	apiURL := fmt.Sprintf("%s/agents/%s/group/%s", c.BaseURL, agentID, groupID)
	req, _ := http.NewRequest(method, apiURL, nil)
	req.Header.Add("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		c.Authenticate()
		req.Header.Set("Authorization", "Bearer "+c.Token)
		resp, _ = c.HTTPClient.Do(req)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var wazuhResp WazuhErrorResponse
	json.Unmarshal(bodyBytes, &wazuhResp)

	if wazuhResp.Error != 0 {
		if method == "PUT" {
			for _, item := range wazuhResp.Data.FailedItems {
				if item.Error.Code == 1751 {
					return nil 
				}
			}
		}
		return fmt.Errorf("api error: %s", wazuhResp.Message)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("http status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}