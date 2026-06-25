package yookassabridge

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr        string
	PublicBaseURL     string
	BasePath          string
	DataFile          string
	YooKassaShopID    string
	YooKassaSecretKey string
	NewAPIBaseURL     string
	NewAPIAdminToken  string
	NewAPIAdminUserID string
	EpayPID           string
	EpayKey           string
	QuotaPerRuble     int
	Plans             []Plan
}

type Plan struct {
	AmountRUB int `json:"amount_rub"`
	Quota     int `json:"quota"`
}

func LoadConfig() (Config, error) {
	cfg := Config{
		ListenAddr:    env("YOOKASSA_BRIDGE_ADDR", ":8090"),
		PublicBaseURL: strings.TrimRight(env("PUBLIC_BASE_URL", "https://vibecode-api.online/pay"), "/"),
		BasePath:      cleanBasePath(env("BASE_PATH", "/pay")),
		DataFile:      env("DATA_FILE", "yookassa-bridge-data.json"),
		NewAPIBaseURL: strings.TrimRight(env("NEW_API_BASE_URL", "https://vibecode-api.online"), "/"),
		QuotaPerRuble: envInt("QUOTA_PER_RUBLE", 500000),
	}
	cfg.YooKassaShopID = strings.TrimSpace(os.Getenv("YOOKASSA_SHOP_ID"))
	cfg.YooKassaSecretKey = strings.TrimSpace(os.Getenv("YOOKASSA_SECRET_KEY"))
	cfg.NewAPIAdminToken = strings.TrimSpace(os.Getenv("NEW_API_ADMIN_TOKEN"))
	cfg.NewAPIAdminUserID = strings.TrimSpace(os.Getenv("NEW_API_ADMIN_USER_ID"))
	cfg.EpayPID = strings.TrimSpace(env("EPAY_PID", "vibecode"))
	cfg.EpayKey = strings.TrimSpace(os.Getenv("EPAY_KEY"))

	plans, err := parsePlans(os.Getenv("TOPUP_PLANS"), cfg.QuotaPerRuble)
	if err != nil {
		return Config{}, err
	}
	cfg.Plans = plans

	if cfg.YooKassaShopID == "" {
		return Config{}, fmt.Errorf("YOOKASSA_SHOP_ID is required")
	}
	if cfg.YooKassaSecretKey == "" {
		return Config{}, fmt.Errorf("YOOKASSA_SECRET_KEY is required")
	}
	if cfg.NewAPIAdminToken == "" {
		return Config{}, fmt.Errorf("NEW_API_ADMIN_TOKEN is required")
	}
	if cfg.NewAPIAdminUserID == "" {
		return Config{}, fmt.Errorf("NEW_API_ADMIN_USER_ID is required")
	}
	if cfg.EpayKey == "" {
		return Config{}, fmt.Errorf("EPAY_KEY is required")
	}
	return cfg, nil
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func cleanBasePath(path string) string {
	path = "/" + strings.Trim(path, "/")
	if path == "/" {
		return ""
	}
	return path
}

func parsePlans(raw string, quotaPerRuble int) ([]Plan, error) {
	if strings.TrimSpace(raw) == "" {
		raw = "100,300,500,1000"
	}
	parts := strings.Split(raw, ",")
	plans := make([]Plan, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		amountText := part
		quota := 0
		if strings.Contains(part, ":") {
			items := strings.SplitN(part, ":", 2)
			amountText = strings.TrimSpace(items[0])
			parsedQuota, err := strconv.Atoi(strings.TrimSpace(items[1]))
			if err != nil || parsedQuota <= 0 {
				return nil, fmt.Errorf("invalid TOPUP_PLANS quota %q", part)
			}
			quota = parsedQuota
		}
		amount, err := strconv.Atoi(amountText)
		if err != nil || amount <= 0 {
			return nil, fmt.Errorf("invalid TOPUP_PLANS amount %q", part)
		}
		if quota == 0 {
			quota = amount * quotaPerRuble
		}
		plans = append(plans, Plan{AmountRUB: amount, Quota: quota})
	}
	if len(plans) == 0 {
		return nil, fmt.Errorf("TOPUP_PLANS must contain at least one amount")
	}
	return plans, nil
}
