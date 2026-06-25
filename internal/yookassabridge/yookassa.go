package yookassabridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type YooKassaClient struct {
	shopID     string
	secretKey  string
	httpClient *http.Client
}

type CreatedPayment struct {
	ID              string
	Status          string
	ConfirmationURL string
}

type YooPayment struct {
	ID       string            `json:"id"`
	Status   string            `json:"status"`
	Paid     bool              `json:"paid"`
	Metadata map[string]string `json:"metadata"`
}

func NewYooKassaClient(shopID, secretKey string) *YooKassaClient {
	return &YooKassaClient{
		shopID:     shopID,
		secretKey:  secretKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *YooKassaClient) CreatePayment(ctx context.Context, order Order, returnURL string) (CreatedPayment, error) {
	metadata := map[string]string{"order_id": order.ID}
	if order.EpayTradeNo != "" {
		metadata["out_trade_no"] = order.EpayTradeNo
	}
	if order.EpayNotifyURL != "" {
		metadata["notify_url"] = order.EpayNotifyURL
	}
	amountValue := fmt.Sprintf("%d.00", order.AmountRUB)
	if order.EpayMoney != "" {
		amountValue = order.EpayMoney
	}
	body := map[string]any{
		"amount": map[string]string{
			"value":    amountValue,
			"currency": "RUB",
		},
		"capture": true,
		"confirmation": map[string]string{
			"type":       "redirect",
			"return_url": returnURL,
		},
		"description": fmt.Sprintf("Пополнение баланса Vibecode API, заказ %s", order.ID),
		"metadata":    metadata,
		"payment_method_data": map[string]string{
			"type": "sbp",
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return CreatedPayment{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.yookassa.ru/v3/payments", bytes.NewReader(payload))
	if err != nil {
		return CreatedPayment{}, err
	}
	req.SetBasicAuth(c.shopID, c.secretKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotence-Key", order.ID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return CreatedPayment{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CreatedPayment{}, decodeAPIError(resp)
	}
	var decoded struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		Confirmation struct {
			URL string `json:"confirmation_url"`
		} `json:"confirmation"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return CreatedPayment{}, err
	}
	return CreatedPayment{ID: decoded.ID, Status: decoded.Status, ConfirmationURL: decoded.Confirmation.URL}, nil
}

func (c *YooKassaClient) GetPayment(ctx context.Context, paymentID string) (YooPayment, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.yookassa.ru/v3/payments/"+paymentID, nil)
	if err != nil {
		return YooPayment{}, err
	}
	req.SetBasicAuth(c.shopID, c.secretKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return YooPayment{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return YooPayment{}, decodeAPIError(resp)
	}
	var payment YooPayment
	if err := json.NewDecoder(resp.Body).Decode(&payment); err != nil {
		return YooPayment{}, err
	}
	return payment, nil
}

func decodeAPIError(resp *http.Response) error {
	var body struct {
		Type        string `json:"type"`
		ID          string `json:"id"`
		Code        string `json:"code"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Description != "" {
		return fmt.Errorf("api status %d: %s", resp.StatusCode, body.Description)
	}
	return fmt.Errorf("api status %d", resp.StatusCode)
}
