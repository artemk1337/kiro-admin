package yookassabridge

import "time"

const (
	OrderPending   = "pending"
	OrderSucceeded = "succeeded"
	OrderCanceled  = "canceled"
	OrderFailed    = "failed"
)

type Order struct {
	ID              string    `json:"id"`
	AmountRUB       int       `json:"amount_rub"`
	Quota           int       `json:"quota"`
	Status          string    `json:"status"`
	YooPaymentID    string    `json:"yoo_payment_id,omitempty"`
	ConfirmationURL string    `json:"confirmation_url,omitempty"`
	RedemptionCode  string    `json:"redemption_code,omitempty"`
	EpayTradeNo     string    `json:"epay_trade_no,omitempty"`
	EpayType        string    `json:"epay_type,omitempty"`
	EpayName        string    `json:"epay_name,omitempty"`
	EpayMoney       string    `json:"epay_money,omitempty"`
	EpayNotifyURL   string    `json:"epay_notify_url,omitempty"`
	EpayReturnURL   string    `json:"epay_return_url,omitempty"`
	EpayNotified    bool      `json:"epay_notified,omitempty"`
	Error           string    `json:"error,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (o Order) canCredit() bool {
	return o.Status != OrderSucceeded || o.RedemptionCode == ""
}
