package yookassabridge

import "testing"

func TestEpaySignVerify(t *testing.T) {
	params := map[string]string{
		"pid":          "vibecode",
		"type":         "sbp",
		"out_trade_no": "USR1NOabc",
		"notify_url":   "https://vibecode-api.online/api/user/epay/notify",
		"name":         "TUC100",
		"money":        "100.00",
		"device":       "pc",
		"return_url":   "https://vibecode-api.online/console/log",
		"sign":         "",
		"sign_type":    "MD5",
	}
	signed := epaySignedParams(params, "secret")
	if !epayVerify(signed, "secret") {
		t.Fatal("signed params must verify")
	}
	if epayVerify(signed, "wrong") {
		t.Fatal("signed params must not verify with wrong key")
	}
}
