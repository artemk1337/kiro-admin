package yookassabridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

type fakeYoo struct {
	paymentID string
	status    string
	paid      bool
}

func (f *fakeYoo) CreatePayment(ctx context.Context, order Order, returnURL string) (CreatedPayment, error) {
	f.paymentID = "pay_" + order.ID
	return CreatedPayment{
		ID:              f.paymentID,
		Status:          "pending",
		ConfirmationURL: "https://yookassa.test/confirm",
	}, nil
}

func (f *fakeYoo) GetPayment(ctx context.Context, paymentID string) (YooPayment, error) {
	return YooPayment{
		ID:     paymentID,
		Status: f.status,
		Paid:   f.paid,
		Metadata: map[string]string{
			"order_id": "",
		},
	}, nil
}

type fakeNewAPI struct {
	calls int
	quota int
}

func (f *fakeNewAPI) CreateRedemption(ctx context.Context, name string, quota int) (string, error) {
	f.calls++
	f.quota = quota
	return "redeem-code", nil
}

func TestWebhookCreatesRedemptionOnce(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	yoo := &fakeYoo{status: "succeeded", paid: true}
	newAPI := &fakeNewAPI{}
	server := NewServer(Config{
		BasePath:      "/pay",
		PublicBaseURL: "https://vibecode-api.online/pay",
		Plans:         []Plan{{AmountRUB: 100, Quota: 5000}},
	}, store, yoo, newAPI)
	handler := server.Handler()

	createBody := bytes.NewBufferString(`{"amount_rub":100}`)
	createReq := httptest.NewRequest(http.MethodPost, "/pay/api/payments", createBody)
	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", createRR.Code, createRR.Body.String())
	}
	var order Order
	if err := json.NewDecoder(createRR.Body).Decode(&order); err != nil {
		t.Fatal(err)
	}

	webhookBody := bytes.NewBufferString(`{"event":"payment.succeeded","object":{"id":"` + order.YooPaymentID + `"}}`)
	webhookReq := httptest.NewRequest(http.MethodPost, "/pay/webhook/yookassa", webhookBody)
	webhookRR := httptest.NewRecorder()
	handler.ServeHTTP(webhookRR, webhookReq)
	if webhookRR.Code != http.StatusOK {
		t.Fatalf("webhook status = %d, body = %s", webhookRR.Code, webhookRR.Body.String())
	}
	if newAPI.calls != 1 || newAPI.quota != 5000 {
		t.Fatalf("new api calls = %d quota = %d, want 1 and 5000", newAPI.calls, newAPI.quota)
	}

	repeatReq := httptest.NewRequest(http.MethodPost, "/pay/webhook/yookassa", bytes.NewBufferString(`{"event":"payment.succeeded","object":{"id":"`+order.YooPaymentID+`"}}`))
	repeatRR := httptest.NewRecorder()
	handler.ServeHTTP(repeatRR, repeatReq)
	if repeatRR.Code != http.StatusOK {
		t.Fatalf("repeat status = %d, body = %s", repeatRR.Code, repeatRR.Body.String())
	}
	if newAPI.calls != 1 {
		t.Fatalf("new api calls after repeat = %d, want 1", newAPI.calls)
	}
}

func TestCreatePaymentRejectsUnknownAmount(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{
		BasePath: "/pay",
		Plans:    []Plan{{AmountRUB: 100, Quota: 5000}},
	}, store, &fakeYoo{}, &fakeNewAPI{})

	req := httptest.NewRequest(http.MethodPost, "/pay/api/payments", bytes.NewBufferString(`{"amount_rub":999}`))
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestEpaySubmitCreatesYooKassaPayment(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	yoo := &fakeYoo{}
	server := NewServer(Config{
		BasePath:      "/pay",
		PublicBaseURL: "https://vibecode-api.online/pay",
		EpayPID:       "vibecode",
		EpayKey:       "secret",
	}, store, yoo, &fakeNewAPI{})

	params := epaySignedParams(map[string]string{
		"pid":          "vibecode",
		"type":         "sbp",
		"out_trade_no": "USR1NOabc",
		"notify_url":   "https://vibecode-api.online/api/user/epay/notify",
		"return_url":   "https://vibecode-api.online/console/log",
		"name":         "TUC100",
		"money":        "100.00",
		"device":       "pc",
	}, "secret")
	form := url.Values{}
	for name, value := range params {
		form.Set(name, value)
	}
	req := httptest.NewRequest(http.MethodPost, "/pay/submit.php", bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Location") != "https://yookassa.test/confirm" {
		t.Fatalf("location = %q", rr.Header().Get("Location"))
	}
	order, ok := store.FindByPaymentID(yoo.paymentID)
	if !ok {
		t.Fatal("order was not stored by payment id")
	}
	if order.EpayTradeNo != "USR1NOabc" || order.EpayMoney != "100.00" {
		t.Fatalf("order = %+v", order)
	}
}

func TestPendingPaymentIDs(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(Order{ID: "one", Status: OrderPending, YooPaymentID: "pay_one"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(Order{ID: "two", Status: OrderSucceeded, YooPaymentID: "pay_two"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(Order{ID: "three", Status: OrderPending}); err != nil {
		t.Fatal(err)
	}
	ids := store.PendingPaymentIDs()
	if len(ids) != 1 || ids[0] != "pay_one" {
		t.Fatalf("pending ids = %#v", ids)
	}
}
