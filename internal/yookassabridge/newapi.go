package yookassabridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type NewAPIClient struct {
	baseURL     string
	adminToken  string
	adminUserID string
	httpClient  *http.Client
}

func NewNewAPIClient(baseURL, adminToken, adminUserID string) *NewAPIClient {
	return &NewAPIClient{
		baseURL:     baseURL,
		adminToken:  adminToken,
		adminUserID: adminUserID,
		httpClient:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *NewAPIClient) CreateRedemption(ctx context.Context, name string, quota int) (string, error) {
	payload, err := json.Marshal(map[string]any{
		"name":         name,
		"quota":        quota,
		"count":        1,
		"expired_time": 0,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/redemption/", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", c.adminToken)
	req.Header.Set("New-Api-User", c.adminUserID)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var decoded struct {
		Success bool     `json:"success"`
		Message string   `json:"message"`
		Data    []string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !decoded.Success {
		if decoded.Message == "" {
			decoded.Message = resp.Status
		}
		return "", fmt.Errorf("new api redemption failed: %s", decoded.Message)
	}
	if len(decoded.Data) == 0 || decoded.Data[0] == "" {
		return "", fmt.Errorf("new api redemption returned empty code")
	}
	return decoded.Data[0], nil
}
