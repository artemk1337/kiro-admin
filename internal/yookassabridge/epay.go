package yookassabridge

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strings"
)

const epayTradeSuccess = "TRADE_SUCCESS"

func epaySignedParams(params map[string]string, key string) map[string]string {
	result := make(map[string]string, len(params)+2)
	for name, value := range params {
		result[name] = value
	}
	result["sign"] = epaySign(result, key)
	result["sign_type"] = "MD5"
	return result
}

func epayVerify(params map[string]string, key string) bool {
	if params["sign"] == "" {
		return false
	}
	return params["sign"] == epaySign(params, key)
}

func epaySign(params map[string]string, key string) string {
	keys := make([]string, 0, len(params))
	for name, value := range params {
		if name == "sign" || name == "sign_type" || value == "" {
			continue
		}
		keys = append(keys, name)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, name := range keys {
		parts = append(parts, name+"="+params[name])
	}
	sum := md5.Sum([]byte(strings.Join(parts, "&") + key))
	return fmt.Sprintf("%x", sum)
}
