package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewOutboundHTTPClientUsesFiveMinuteTimeout(t *testing.T) {
	client := newOutboundHTTPClient()
	if client.Timeout != 5*time.Minute {
		t.Fatalf("timeout = %s, want 5m0s", client.Timeout)
	}
}

func TestAdminHTMLHasAPIKeyCopyButton(t *testing.T) {
	if !strings.Contains(adminHTML, "copyAPIKey") {
		t.Fatal("admin HTML should include API key copy handler")
	}
	if !strings.Contains(adminHTML, "Копировать sk-ключ") {
		t.Fatal("admin HTML should include API key copy button title")
	}
}

func TestAdminHTMLAcceptsBuilderIDTokenJSON(t *testing.T) {
	for _, want := range []string{"kas.oauth_flow", "kas.start_url", "kas.client_id", "kas.client_secret", "kas.accessToken", "kas.refreshToken"} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin HTML should parse %s", want)
		}
	}
	if strings.Contains(adminHTML, "profile_arn')") || strings.Contains(adminHTML, "profile_arn and") {
		t.Fatal("admin HTML should not require profile_arn")
	}
}

func TestAdminHTMLHasAuthorizationFlow(t *testing.T) {
	for _, want := range []string{"Авторизация", "startAdminAuthorization", "/admin/api/auth/start", "authBox", "kasJson.value=JSON.stringify"} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin HTML should include auth flow piece %s", want)
		}
	}
	rightColumnAuth := `<section>
          <div class="auth-panel">
            <h2>Авторизация</h2>`
	if !strings.Contains(adminHTML, rightColumnAuth) {
		t.Fatal("admin auth button should be in the right column")
	}
	if !strings.Contains(adminHTML, ".auth-box { display:grid; width:100%;") {
		t.Fatal("admin auth status should use full width layout")
	}
}

func TestAdminHTMLHasInlineAccountToggle(t *testing.T) {
	if !strings.Contains(adminHTML, "power-toggle") {
		t.Fatal("admin HTML should include inline account toggle")
	}
	if !strings.Contains(adminHTML, "account-head") {
		t.Fatal("admin HTML should render account toggle near the account status")
	}
	if !strings.Contains(adminHTML, "const statusClass=!enabled?'':(a.status==='ok'?'active':'error')") {
		t.Fatal("disabled accounts should render with neutral status color")
	}
	if !strings.Contains(adminHTML, "cubic-bezier(.22,1,.36,1)") {
		t.Fatal("account toggle should include smooth motion easing")
	}
}

func TestAdminHTMLHasGroupsUI(t *testing.T) {
	for _, want := range []string{"groupsView", "accountGroupFilter", "accountGroupSelect", "groupForm", "rotateGroupKey"} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin HTML should include %s", want)
		}
	}
}

func TestAdminHTMLRefreshesGroupsAfterCreate(t *testing.T) {
	for _, want := range []string{"const result=await api('/admin/api/groups'", "settings.groups=result.groups", "renderSettings()"} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin HTML should refresh groups after create; missing %s", want)
		}
	}
}

func TestAdminHTMLUsageSkipsDisabledAccounts(t *testing.T) {
	if !strings.Contains(adminHTML, "if(a.enabled===false) continue") {
		t.Fatal("admin HTML should skip disabled accounts in credits metric")
	}
}

func TestAdminHTMLHasGrafanaStyleTimeRangePicker(t *testing.T) {
	for _, want := range []string{"timeRangePicker", "timeRangeButton", "timeRangeMenu", "refreshNow", "historyFrom", "historyTo", "applyHistoryRange", "last_24h"} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin HTML should include %s", want)
		}
	}
	if !strings.Contains(adminHTML, "time-toolbar") {
		t.Fatal("admin HTML should render compact time toolbar")
	}
	if strings.Contains(adminHTML, `select id="historyRange"`) {
		t.Fatal("admin HTML should not use old history range select")
	}
}

func TestAdminAuthDeviceFlowReturnsKASJSON(t *testing.T) {
	oidcLoginSessions.Lock()
	oidcLoginSessions.byID = nil
	oidcLoginSessions.Unlock()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/client/register":
			var req struct {
				ClientName string   `json:"clientName"`
				ClientType string   `json:"clientType"`
				Scopes     []string `json:"scopes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode register request: %v", err)
			}
			if req.ClientName != kiroOIDCClientName || req.ClientType != kiroOIDCClientType {
				t.Fatalf("register request = %+v", req)
			}
			if strings.Join(req.Scopes, ",") != strings.Join(kiroOIDCScopes, ",") {
				t.Fatalf("register scopes = %+v", req.Scopes)
			}
			_, _ = w.Write([]byte(`{"clientId":"client-id","clientSecret":"client-secret","clientSecretExpiresAt":1780000000,"tokenEndpoint":"token"}`))
		case "/device_authorization":
			var req struct {
				ClientID     string `json:"clientId"`
				ClientSecret string `json:"clientSecret"`
				StartURL     string `json:"startUrl"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode device request: %v", err)
			}
			if req.ClientID != "client-id" || req.ClientSecret != "client-secret" || req.StartURL != kiroOIDCStartURL {
				t.Fatalf("device request = %+v", req)
			}
			_, _ = w.Write([]byte(`{"deviceCode":"device-code","userCode":"ABCD-EFGH","verificationUri":"https://example.test/verify","verificationUriComplete":"https://example.test/verify?user_code=ABCD-EFGH","expiresIn":600,"interval":1}`))
		case "/token":
			var req struct {
				ClientID     string `json:"clientId"`
				ClientSecret string `json:"clientSecret"`
				GrantType    string `json:"grantType"`
				DeviceCode   string `json:"deviceCode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			if req.ClientID != "client-id" || req.ClientSecret != "client-secret" || req.GrantType != kiroOIDCDeviceGrantType || req.DeviceCode != "device-code" {
				t.Fatalf("token request = %+v", req)
			}
			_, _ = w.Write([]byte(`{"accessToken":"access","refreshToken":"refresh","expiresIn":3600,"tokenType":"Bearer"}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	oldRegisterEndpoint := kiroOIDCRegisterEndpoint
	oldDeviceEndpoint := kiroOIDCDeviceAuthEndpoint
	oldTokenEndpoint := kiroOIDCTokenEndpoint
	kiroOIDCRegisterEndpoint = server.URL + "/client/register"
	kiroOIDCDeviceAuthEndpoint = server.URL + "/device_authorization"
	kiroOIDCTokenEndpoint = server.URL + "/token"
	defer func() {
		kiroOIDCRegisterEndpoint = oldRegisterEndpoint
		kiroOIDCDeviceAuthEndpoint = oldDeviceEndpoint
		kiroOIDCTokenEndpoint = oldTokenEndpoint
	}()

	startReq := httptest.NewRequest(http.MethodPost, "/admin/api/auth/start", nil)
	startRec := httptest.NewRecorder()
	handleAdminAuthStart(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("start status = %d, body = %s", startRec.Code, startRec.Body.String())
	}
	var started struct {
		ID       string `json:"id"`
		UserCode string `json:"userCode"`
	}
	if err := json.NewDecoder(startRec.Body).Decode(&started); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if started.ID == "" || started.UserCode != "ABCD-EFGH" {
		t.Fatalf("start response = %+v", started)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/admin/api/auth/"+started.ID, nil)
	statusRec := httptest.NewRecorder()
	handleAdminAuthStatus(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", statusRec.Code, statusRec.Body.String())
	}
	var status struct {
		Status  string `json:"status"`
		KASJSON struct {
			AccessToken        string   `json:"access_token"`
			RefreshToken       string   `json:"refresh_token"`
			Region             string   `json:"region"`
			StartURL           string   `json:"start_url"`
			OAuthFlow          string   `json:"oauth_flow"`
			Scopes             []string `json:"scopes"`
			ClientID           string   `json:"client_id"`
			ClientSecret       string   `json:"client_secret"`
			ClientSecretExpiry string   `json:"client_secret_expires_at"`
		} `json:"kasJson"`
	}
	if err := json.NewDecoder(statusRec.Body).Decode(&status); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if status.Status != "complete" {
		t.Fatalf("auth status = %q, want complete", status.Status)
	}
	if status.KASJSON.AccessToken != "access" || status.KASJSON.RefreshToken != "refresh" {
		t.Fatalf("kas json token = %+v", status.KASJSON)
	}
	if status.KASJSON.ClientID != "client-id" || status.KASJSON.ClientSecret != "client-secret" {
		t.Fatalf("kas json client registration = %+v", status.KASJSON)
	}
	if status.KASJSON.OAuthFlow != "DeviceCode" || status.KASJSON.StartURL != kiroOIDCStartURL || len(status.KASJSON.Scopes) != len(kiroOIDCScopes) {
		t.Fatalf("kas json metadata = %+v", status.KASJSON)
	}
	if status.KASJSON.ClientSecretExpiry == "" {
		t.Fatalf("client secret expiry is empty")
	}
}

func TestWriteListAndSelectTokenAccounts(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))
	t.Setenv("KIRO2CC_ACCOUNT", "")

	_, err := writeTokenAccount("work", TokenData{
		AccessToken:  "access-work",
		RefreshToken: "refresh-work",
		ExpiresAt:    "2026-01-01T00:00:00Z",
		ProfileArn:   "arn:aws:codewhisperer:us-east-1:699475941385:profile/work",
	})
	if err != nil {
		t.Fatalf("write account: %v", err)
	}
	_, err = writeTokenAccount("personal", TokenData{
		AccessToken:  "access-personal",
		RefreshToken: "refresh-personal",
		ProfileArn:   "arn:aws:codewhisperer:us-east-1:699475941385:profile/personal",
	})
	if err != nil {
		t.Fatalf("write second account: %v", err)
	}

	accounts, err := listTokenAccounts()
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("accounts count = %d, want 2", len(accounts))
	}

	selected, err := selectTokenAccount("personal")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if selected.Token.AccessToken != "access-personal" {
		t.Fatalf("selected access token = %q", selected.Token.AccessToken)
	}
}

func TestGetStreamDeltaText(t *testing.T) {
	got := getStreamDeltaText(map[string]any{
		"delta": map[string]any{
			"type": "text_delta",
			"text": "hello",
		},
	})
	if got != "hello" {
		t.Fatalf("delta text = %q, want hello", got)
	}

	if got := getStreamDeltaText(map[string]any{"delta": map[string]any{"type": "input_json_delta"}}); got != "" {
		t.Fatalf("non-text delta = %q, want empty", got)
	}
	if got := getStreamDeltaText("bad"); got != "" {
		t.Fatalf("bad delta = %q, want empty", got)
	}
}

func TestRequestStatsOrdersWorstAccountsFirst(t *testing.T) {
	stats := requestStats([]RequestLogEntry{
		{Account: "stable", Status: http.StatusOK, DurationMs: 100},
		{Account: "bad", Status: http.StatusBadGateway, DurationMs: 200, Error: `CodeWhisperer status: 429, response: {"message":"Too many requests"}`},
		{Account: "bad", Status: http.StatusOK, DurationMs: 100},
	})
	if stats.Total != 3 || stats.Success != 2 || stats.Failed != 1 {
		t.Fatalf("stats = %+v, want total=3 success=2 failed=1", stats)
	}
	if stats.ErrorCounts["429 Too many requests"] != 1 {
		t.Fatalf("error counts = %+v, want Too many requests", stats.ErrorCounts)
	}
	if len(stats.Accounts) == 0 || stats.Accounts[0].Name != "bad" {
		t.Fatalf("accounts = %+v, want bad first", stats.Accounts)
	}
}

func TestFilterRequestHistoryByDateAndStatsReset(t *testing.T) {
	oldNow := nowFunc
	nowFunc = func() time.Time {
		return time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	}
	defer func() { nowFunc = oldNow }()

	entries := []RequestLogEntry{
		{ID: "today", Time: "2026-06-16T10:00:00Z", Status: http.StatusOK},
		{ID: "yesterday", Time: "2026-06-15T10:00:00Z", Status: http.StatusBadGateway},
		{ID: "old", Time: "2026-06-01T10:00:00Z", Status: http.StatusOK},
	}
	today := filterRequestHistory(entries, "today", "", "", "")
	if len(today) != 1 || today[0].ID != "today" {
		t.Fatalf("today entries = %+v, want only today", today)
	}
	reset := filterRequestHistory(entries, "all", "2026-06-15T12:00:00Z", "", "")
	if len(reset) != 1 || reset[0].ID != "today" {
		t.Fatalf("reset entries = %+v, want only after reset", reset)
	}
	custom := filterRequestHistory(entries, "all", "", "2026-06-15T00:00:00Z", "2026-06-16T00:00:00Z")
	if len(custom) != 1 || custom[0].ID != "yesterday" {
		t.Fatalf("custom entries = %+v, want only yesterday", custom)
	}
}

func TestOpenAIRequestToAnthropic(t *testing.T) {
	temp := 0.2
	got, err := openAIRequestToAnthropic(OpenAIChatCompletionRequest{
		Model:       "claude-haiku-4.5",
		Stream:      true,
		Temperature: &temp,
		Messages: []OpenAIChatMessage{
			{Role: "system", Content: "Ты полезный ассистент"},
			{Role: "user", Content: []any{
				map[string]any{"type": "text", "text": "Привет"},
				map[string]any{"type": "input_text", "text": "Как дела?"},
			}},
		},
		Tools: []OpenAIChatTool{{
			Type: "function",
			Function: OpenAIChatFunction{
				Name:        "lookup",
				Description: "search",
				Parameters:  map[string]any{"type": "object"},
			},
		}},
	})
	if err != nil {
		t.Fatalf("convert request: %v", err)
	}
	if got.Model != "claude-haiku-4.5" || !got.Stream || got.Temperature != &temp {
		t.Fatalf("request fields = %+v", got)
	}
	if len(got.System) != 1 || got.System[0].Text != "Ты полезный ассистент" {
		t.Fatalf("system = %+v", got.System)
	}
	if len(got.Messages) != 1 || got.Messages[0].Role != "user" || got.Messages[0].Content != "Привет\nКак дела?" {
		t.Fatalf("messages = %+v", got.Messages)
	}
	if len(got.Tools) != 1 || got.Tools[0].Name != "lookup" {
		t.Fatalf("tools = %+v", got.Tools)
	}
}

func TestHandleOpenAIChatCompletions(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := writeTokenAccount("work", TokenData{
		AccessToken:  "kas-access",
		RefreshToken: "kas-refresh",
		ProfileArn:   "arn:test",
		APIKey:       "sk-test",
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer kas-access" {
			t.Fatalf("authorization = %q", got)
		}
		var req CodeWhispererRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode codewhisperer request: %v", err)
		}
		if req.ConversationState.CurrentMessage.UserInputMessage.Content != "Ты кто?" {
			t.Fatalf("content = %q, want user text", req.ConversationState.CurrentMessage.UserInputMessage.Content)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(codeWhispererTestEvent(`{"content":"Я Kiro.","stop":true}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererGenerateEndpoint
	codeWhispererGenerateEndpoint = server.URL
	defer func() { codeWhispererGenerateEndpoint = oldEndpoint }()

	body := bytes.NewBufferString(`{"model":"claude-haiku-4.5","messages":[{"role":"user","content":"Ты кто?"}],"stream":false}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
	req.Header.Set("Authorization", "Bearer sk-test")
	rr := httptest.NewRecorder()
	handleOpenAIChatCompletions(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Object  string `json:"object"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Object != "chat.completion" || len(resp.Choices) != 1 {
		t.Fatalf("response = %+v", resp)
	}
	if resp.Choices[0].Message.Role != "assistant" || resp.Choices[0].Message.Content != "Я Kiro." {
		t.Fatalf("message = %+v", resp.Choices[0].Message)
	}
	if resp.Usage.TotalTokens == 0 {
		t.Fatalf("total tokens is zero")
	}
}

func codeWhispererTestEvent(payload string) []byte {
	body := []byte("vent" + payload)
	totalLen := uint32(12 + len(body))
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, totalLen)
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	buf.Write(body)
	buf.Write([]byte{0, 0, 0, 0})
	return buf.Bytes()
}

func TestSelectTokenAccountWithoutNameUsesFirstAccount(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))
	t.Setenv("KIRO2CC_ACCOUNT", "")

	if _, err := writeTokenAccount("work", TokenData{AccessToken: "a1", RefreshToken: "r1", ProfileArn: "arn:work"}); err != nil {
		t.Fatalf("write work: %v", err)
	}
	if _, err := writeTokenAccount("team", TokenData{AccessToken: "a2", RefreshToken: "r2", ProfileArn: "arn:team"}); err != nil {
		t.Fatalf("write team: %v", err)
	}

	selected, err := selectTokenAccount("")
	if err != nil {
		t.Fatalf("select default account: %v", err)
	}
	if selected.Name == "" {
		t.Fatalf("selected account name is empty")
	}
}

func TestSelectTokenAccountByAPIKey(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	_, err := writeTokenAccount("work", TokenData{
		AccessToken:  "a1",
		RefreshToken: "r1",
		ProfileArn:   "arn:work",
		APIKey:       "sk-work",
	})
	if err != nil {
		t.Fatalf("write work: %v", err)
	}

	selected, err := selectTokenAccountByAPIKey("sk-work")
	if err != nil {
		t.Fatalf("select by api key: %v", err)
	}
	if selected.Name != "work" {
		t.Fatalf("selected account = %q, want work", selected.Name)
	}
}

func TestWriteTokenAccountSanitizesName(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	account, err := writeTokenAccount("../bad name", TokenData{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ProfileArn:   "arn:profile",
	})
	if err != nil {
		t.Fatalf("write account: %v", err)
	}

	if account.Name != "bad-name" {
		t.Fatalf("sanitized name = %q, want bad-name", account.Name)
	}
	if filepath.Dir(account.Path) != tokenDir {
		t.Fatalf("account path escaped token dir: %s", account.Path)
	}
	if _, err := os.Stat(account.Path); err != nil {
		t.Fatalf("account file was not written: %v", err)
	}
}

func TestWriteTokenAccountRequiresRefreshToken(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	_, err := writeTokenAccount("kiro-cli", TokenData{
		AccessToken: "kas-access",
		ExpiresAt:   "2026-06-10T18:10:07Z",
		ProfileArn:  "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
	})
	if err == nil {
		t.Fatal("write account error is nil")
	}
	if !strings.Contains(err.Error(), "refreshToken") {
		t.Fatalf("error = %q, want refreshToken", err)
	}
}

func TestWriteTokenAccountAllowsMissingProfileArn(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	_, err := writeTokenAccount("builder-id", TokenData{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    "2026-06-10T18:10:07Z",
		Region:       "us-east-1",
		StartURL:     "https://view.awsapps.com/start",
		OAuthFlow:    "PKCE",
		Scopes:       []string{"codewhisperer:completions"},
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	})
	if err != nil {
		t.Fatalf("write account: %v", err)
	}

	account, err := selectTokenAccount("builder-id")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if account.Token.ProfileArn != "" {
		t.Fatalf("profileArn = %q, want empty", account.Token.ProfileArn)
	}
	if account.Token.OAuthFlow != "PKCE" || account.Token.StartURL == "" || len(account.Token.Scopes) != 1 || account.Token.ClientID != "client-id" || account.Token.ClientSecret != "client-secret" {
		t.Fatalf("token metadata was not preserved: %+v", account.Token)
	}
}

func TestWriteTokenAccountAppliesDefaultLimits(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	account, err := writeTokenAccount("work", TokenData{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ProfileArn:   "arn:test",
	})
	if err != nil {
		t.Fatalf("write account: %v", err)
	}
	if account.Token.RPS != defaultAccountRPS {
		t.Fatalf("rps = %v, want %v", account.Token.RPS, defaultAccountRPS)
	}
	if account.Token.Concurrency != defaultAccountConcurrency {
		t.Fatalf("concurrency = %d, want %d", account.Token.Concurrency, defaultAccountConcurrency)
	}
}

func TestWriteTokenAccountAppliesDefaultGroup(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	account, err := writeTokenAccount("work", TokenData{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ProfileArn:   "arn:test",
	})
	if err != nil {
		t.Fatalf("write account: %v", err)
	}
	if account.Token.Group != defaultAccountGroup {
		t.Fatalf("group = %q, want %q", account.Token.Group, defaultAccountGroup)
	}
}

func TestSelectBalancedTokenAccountUsesModelAvailability(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if err := saveAdminSettings(AdminSettings{Groups: []AccountGroup{{Name: defaultAccountGroup, APIKey: "sk-global"}}}); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	if _, err := writeTokenAccount("slow", TokenData{
		AccessToken:  "kas-slow",
		RefreshToken: "refresh",
		ExpiresAt:    "2030-06-10T22:51:18Z",
		ProfileArn:   "arn:slow",
		APIKey:       "sk-slow",
	}); err != nil {
		t.Fatalf("write slow account: %v", err)
	}
	if _, err := writeTokenAccount("fast", TokenData{
		AccessToken:  "kas-fast",
		RefreshToken: "refresh",
		ExpiresAt:    "2030-06-10T22:51:18Z",
		ProfileArn:   "arn:fast",
		APIKey:       "sk-fast",
	}); err != nil {
		t.Fatalf("write fast account: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer kas-slow":
			_, _ = w.Write([]byte(`{"models":[{"modelId":"claude-sonnet-4"}]}`))
		case "Bearer kas-fast":
			_, _ = w.Write([]byte(`{"models":[{"modelId":"claude-haiku-4.5"}]}`))
		default:
			t.Fatalf("unexpected authorization = %q", r.Header.Get("Authorization"))
		}
	}))
	defer server.Close()

	oldEndpoint := codeWhispererListModelsEndpoint
	codeWhispererListModelsEndpoint = server.URL
	defer func() { codeWhispererListModelsEndpoint = oldEndpoint }()

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("x-api-key", "sk-global")
	account, release, err := selectTokenAccountForRequest(req, "claude-haiku-4.5")
	if release != nil {
		defer release()
	}
	if err != nil {
		t.Fatalf("select balanced account: %v", err)
	}
	if account.Name != "fast" {
		t.Fatalf("account = %q, want fast", account.Name)
	}
}

func TestSelectBalancedTokenAccountStaysInsideGroup(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if err := saveAdminSettings(AdminSettings{Groups: []AccountGroup{
		{Name: "team-a", APIKey: "sk-team-a"},
		{Name: "team-b", APIKey: "sk-team-b"},
	}}); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	if _, err := writeTokenAccount("a", TokenData{
		AccessToken:  "kas-a",
		RefreshToken: "refresh",
		ExpiresAt:    "2030-06-10T22:51:18Z",
		ProfileArn:   "arn:a",
		APIKey:       "sk-a",
		Group:        "team-a",
	}); err != nil {
		t.Fatalf("write team-a account: %v", err)
	}
	if _, err := writeTokenAccount("b", TokenData{
		AccessToken:  "kas-b",
		RefreshToken: "refresh",
		ExpiresAt:    "2030-06-10T22:51:18Z",
		ProfileArn:   "arn:b",
		APIKey:       "sk-b",
		Group:        "team-b",
	}); err != nil {
		t.Fatalf("write team-b account: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("x-api-key", "sk-team-b")
	account, release, err := selectTokenAccountForRequest(req, "auto")
	if release != nil {
		defer release()
	}
	if err != nil {
		t.Fatalf("select balanced account: %v", err)
	}
	if account.Name != "b" {
		t.Fatalf("account = %q, want b", account.Name)
	}
}

func TestSelectBalancedTokenAccountSkipsDisabledAndEmptyCredits(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	zero := 0.0
	credits := 10.0
	if _, err := writeTokenAccount("disabled", TokenData{
		AccessToken:      "kas-disabled",
		RefreshToken:     "refresh",
		ExpiresAt:        "2030-06-10T22:51:18Z",
		ProfileArn:       "arn:disabled",
		APIKey:           "sk-disabled",
		Disabled:         true,
		CreditsRemaining: &credits,
	}); err != nil {
		t.Fatalf("write disabled account: %v", err)
	}
	if _, err := writeTokenAccount("empty", TokenData{
		AccessToken:      "kas-empty",
		RefreshToken:     "refresh",
		ExpiresAt:        "2030-06-10T22:51:18Z",
		ProfileArn:       "arn:empty",
		APIKey:           "sk-empty",
		CreditsRemaining: &zero,
	}); err != nil {
		t.Fatalf("write empty account: %v", err)
	}
	if _, err := writeTokenAccount("ready", TokenData{
		AccessToken:      "kas-ready",
		RefreshToken:     "refresh",
		ExpiresAt:        "2030-06-10T22:51:18Z",
		ProfileArn:       "arn:ready",
		APIKey:           "sk-ready",
		CreditsRemaining: &credits,
	}); err != nil {
		t.Fatalf("write ready account: %v", err)
	}

	account, release, err := selectBalancedTokenAccount(defaultAccountGroup, "auto")
	if release != nil {
		defer release()
	}
	if err != nil {
		t.Fatalf("select balanced account: %v", err)
	}
	if account.Name != "ready" {
		t.Fatalf("account = %q, want ready", account.Name)
	}
}

func TestFetchAvailableModelsDisablesBlockedAccount(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	credits := 50.0
	duration := int64(100)
	if _, err := writeTokenAccount("blocked", TokenData{
		AccessToken:        "kas-blocked",
		RefreshToken:       "refresh",
		ExpiresAt:          "2030-06-10T22:51:18Z",
		ProfileArn:         "arn:blocked",
		APIKey:             "sk-blocked",
		CreditsRemaining:   &credits,
		LastTestDurationMs: &duration,
	}); err != nil {
		t.Fatalf("write blocked account: %v", err)
	}

	modelsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","message":"Your User ID temporarily is suspended. We've locked your account as a security precaution."}`))
	}))
	defer modelsServer.Close()

	oldModelsEndpoint := codeWhispererListModelsEndpoint
	codeWhispererListModelsEndpoint = modelsServer.URL
	defer func() { codeWhispererListModelsEndpoint = oldModelsEndpoint }()

	account, err := selectTokenAccount("blocked")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	_, err = fetchAvailableModels(account)
	if err == nil || !strings.Contains(err.Error(), "заблокирован") {
		t.Fatalf("err = %v, want blocked account", err)
	}

	account, err = selectTokenAccount("blocked")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if !account.Token.Disabled {
		t.Fatal("blocked account should be disabled")
	}
	if !strings.Contains(account.Token.LastCheckError, "заблокирован") {
		t.Fatalf("lastCheckError = %q, want blocked account", account.Token.LastCheckError)
	}
}

func TestHandleAdminAccountToggleChangesEnabledState(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := writeTokenAccount("work", TokenData{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ProfileArn:   "arn:test",
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	rr := httptest.NewRecorder()
	handleAdminAccountAction(rr, httptest.NewRequest(http.MethodPost, "/admin/api/accounts/work/toggle", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp AccountInfo
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Enabled {
		t.Fatalf("enabled = true, want false after toggle")
	}

	account, err := selectTokenAccount("work")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if !account.Token.Disabled {
		t.Fatalf("account disabled = false, want true")
	}
}

func TestHandleAdminAccountsEditPreservesEnabledState(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := writeTokenAccount("work", TokenData{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ProfileArn:   "arn:old",
		Disabled:     true,
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	body := bytes.NewBufferString(`{"name":"work","accessToken":"new-access","refreshToken":"new-refresh","profileArn":"arn:new"}`)
	rr := httptest.NewRecorder()
	handleAdminAccounts(rr, httptest.NewRequest(http.MethodPost, "/admin/api/accounts", body))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	account, err := selectTokenAccount("work")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if !account.Token.Disabled {
		t.Fatalf("disabled = false, want preserved true")
	}
}

func TestHandleAdminAccountsAcceptsBuilderIDTokenWithoutProfileArn(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	body := bytes.NewBufferString(`{
		"name":"builder",
		"accessToken":"access",
		"refreshToken":"refresh",
		"expiresAt":"2026-06-16T11:53:34.314738Z",
		"region":"us-east-1",
		"startUrl":"https://view.awsapps.com/start",
		"oauthFlow":"PKCE",
		"scopes":["codewhisperer:completions","codewhisperer:analysis"],
		"clientId":"client-id",
		"clientSecret":"client-secret",
		"clientSecretExpiresAt":"2026-12-31T00:00:00Z"
	}`)
	rr := httptest.NewRecorder()
	handleAdminAccounts(rr, httptest.NewRequest(http.MethodPost, "/admin/api/accounts", body))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	account, err := selectTokenAccount("builder")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if account.Token.ProfileArn != "" {
		t.Fatalf("profileArn = %q, want empty", account.Token.ProfileArn)
	}
	if account.Token.OAuthFlow != "PKCE" || account.Token.Region != "us-east-1" || len(account.Token.Scopes) != 2 || account.Token.ClientID != "client-id" || account.Token.ClientSecret != "client-secret" {
		t.Fatalf("token metadata was not saved: %+v", account.Token)
	}
}

func TestTokenAccountInfoReportsStatus(t *testing.T) {
	zero := 0.0
	info := tokenAccountInfo(TokenAccount{
		Name: "empty",
		Token: TokenData{
			AccessToken:      "access",
			RefreshToken:     "refresh",
			ProfileArn:       "arn:test",
			CreditsRemaining: &zero,
		},
	}, "")
	if info.Status != "error" || info.StatusMessage != "Credits закончились" {
		t.Fatalf("status = %q %q, want credits error", info.Status, info.StatusMessage)
	}

	credits := 10.0
	duration := int64(123)
	info = tokenAccountInfo(TokenAccount{
		Name: "ready",
		Token: TokenData{
			AccessToken:        "access",
			RefreshToken:       "refresh",
			ProfileArn:         "arn:test",
			CreditsRemaining:   &credits,
			LastTestDurationMs: &duration,
		},
	}, "")
	if info.Status != "ok" {
		t.Fatalf("status = %q, want ok: %+v", info.Status, info)
	}
}

func TestTokenAccountInfoReportsLastCheckError(t *testing.T) {
	info := tokenAccountInfo(TokenAccount{
		Name: "banned",
		Token: TokenData{
			AccessToken:    "access",
			RefreshToken:   "refresh",
			LastCheckError: "Аккаунт заблокирован Kiro/AWS",
		},
	}, "")
	if info.Status != "error" || !strings.Contains(info.StatusMessage, "заблокирован") {
		t.Fatalf("status = %q %q, want blocked account", info.Status, info.StatusMessage)
	}
}

func TestAccountGroupInfosSumCreditsForEnabledAccounts(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	enabledCredits := 10.0
	disabledCredits := 40.0
	if _, err := writeTokenAccount("enabled", TokenData{
		AccessToken:      "kas-enabled",
		RefreshToken:     "refresh",
		Group:            defaultAccountGroup,
		CreditsRemaining: &enabledCredits,
	}); err != nil {
		t.Fatalf("write enabled account: %v", err)
	}
	if _, err := writeTokenAccount("disabled", TokenData{
		AccessToken:      "kas-disabled",
		RefreshToken:     "refresh",
		Group:            defaultAccountGroup,
		CreditsRemaining: &disabledCredits,
		Disabled:         true,
	}); err != nil {
		t.Fatalf("write disabled account: %v", err)
	}

	infos := accountGroupInfos(AdminSettings{Groups: []AccountGroup{{Name: defaultAccountGroup, APIKey: "sk-group"}}})
	if len(infos) != 1 {
		t.Fatalf("groups = %d, want 1", len(infos))
	}
	info := infos[0]
	if info.Accounts != 2 || info.Enabled != 1 {
		t.Fatalf("accounts = %d enabled = %d, want 2/1", info.Accounts, info.Enabled)
	}
	if info.Credits == nil || *info.Credits != enabledCredits {
		t.Fatalf("credits = %v, want %v", info.Credits, enabledCredits)
	}
}

func TestGroupCreditsForRequestSkipsDisabledAccounts(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	disabledCredits := 40.0
	if _, err := writeTokenAccount("enabled", TokenData{
		AccessToken:  "kas-enabled",
		RefreshToken: "refresh",
		ExpiresAt:    "2030-06-10T22:51:18Z",
		ProfileArn:   "arn:enabled",
		Group:        defaultAccountGroup,
	}); err != nil {
		t.Fatalf("write enabled account: %v", err)
	}
	if _, err := writeTokenAccount("disabled", TokenData{
		AccessToken:      "kas-disabled",
		RefreshToken:     "refresh",
		ExpiresAt:        "2030-06-10T22:51:18Z",
		ProfileArn:       "arn:disabled",
		Group:            defaultAccountGroup,
		CreditsRemaining: &disabledCredits,
		Disabled:         true,
	}); err != nil {
		t.Fatalf("write disabled account: %v", err)
	}

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		_, _ = w.Write([]byte(`{"usageBreakdownList":[{"resourceType":"CREDIT","currentUsageWithPrecision":1,"usageLimitWithPrecision":10}]}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererUsageEndpoint
	codeWhispererUsageEndpoint = server.URL
	defer func() { codeWhispererUsageEndpoint = oldEndpoint }()

	account, available, err := groupCreditsForRequest(defaultAccountGroup)
	if err != nil {
		t.Fatalf("group credits: %v", err)
	}
	if account.Name != defaultAccountGroup {
		t.Fatalf("account name = %q, want group name", account.Name)
	}
	if available != 9 {
		t.Fatalf("available = %v, want 9", available)
	}
	if calls != 1 {
		t.Fatalf("usage calls = %d, want 1", calls)
	}
}

func TestWriteTokenAccountUpdatesExistingAccount(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	first, err := writeTokenAccount("work", TokenData{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ProfileArn:   "arn:old",
		APIKey:       "sk-stable",
	})
	if err != nil {
		t.Fatalf("write first account: %v", err)
	}
	second, err := writeTokenAccount("work", TokenData{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		ProfileArn:   "arn:new",
		APIKey:       "sk-stable",
	})
	if err != nil {
		t.Fatalf("update account: %v", err)
	}
	if second.Path != first.Path {
		t.Fatalf("path = %q, want %q", second.Path, first.Path)
	}

	selected, err := selectTokenAccount("work")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if selected.Token.AccessToken != "new-access" || selected.Token.RefreshToken != "new-refresh" {
		t.Fatalf("token was not updated: %+v", selected.Token)
	}
	if selected.Token.APIKey != "sk-stable" {
		t.Fatalf("api key = %q, want sk-stable", selected.Token.APIKey)
	}
}

func TestRequestHistoryPersistsLast1000Entries(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)

	requestHistory.Lock()
	requestHistory.entries = nil
	requestHistory.Unlock()

	for i := 0; i < maxRequestHistory+5; i++ {
		addRequestHistory(RequestLogEntry{
			ID:      string(rune('a' + i%26)),
			Account: "work",
			Status:  http.StatusOK,
		})
	}

	entries := getRequestHistory()
	if len(entries) != maxRequestHistory {
		t.Fatalf("history len = %d, want %d", len(entries), maxRequestHistory)
	}

	requestHistory.Lock()
	requestHistory.entries = nil
	requestHistory.Unlock()
	loadRequestHistory()

	entries = getRequestHistory()
	if len(entries) != maxRequestHistory {
		t.Fatalf("loaded history len = %d, want %d", len(entries), maxRequestHistory)
	}
}

func TestUpdateRequestHistoryCreditsSpent(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)

	requestHistory.Lock()
	requestHistory.entries = nil
	requestHistory.Unlock()
	defer func() {
		requestHistory.Lock()
		requestHistory.entries = nil
		requestHistory.Unlock()
	}()

	addRequestHistory(RequestLogEntry{
		ID:      "req-1",
		Account: "work",
		Status:  http.StatusOK,
	})
	updateRequestHistoryCreditsSpent("req-1", 0.0123)

	entries := getRequestHistory()
	if len(entries) != 1 {
		t.Fatalf("history len = %d, want 1", len(entries))
	}
	if entries[0].CreditsSpent == nil || *entries[0].CreditsSpent != 0.0123 {
		t.Fatalf("credits spent = %v, want 0.0123", entries[0].CreditsSpent)
	}

	requestHistory.Lock()
	requestHistory.entries = nil
	requestHistory.Unlock()
	loadRequestHistory()

	entries = getRequestHistory()
	if len(entries) != 1 || entries[0].CreditsSpent == nil || *entries[0].CreditsSpent != 0.0123 {
		t.Fatalf("persisted credits spent not loaded: %+v", entries)
	}
}

func TestCreditsRemainingFromUsage(t *testing.T) {
	remaining, err := creditsRemainingFromUsage(CodeWhispererUsageResponse{
		UsageBreakdownList: []CodeWhispererUsageBreakdown{{
			ResourceType:              "CREDIT",
			CurrentUsageWithPrecision: 0.26,
			UsageLimitWithPrecision:   50,
		}},
	})
	if err != nil {
		t.Fatalf("credits remaining: %v", err)
	}
	if remaining < 49.739 || remaining > 49.741 {
		t.Fatalf("remaining = %v, want 49.74", remaining)
	}
}

func TestTokenExpiryError(t *testing.T) {
	now := time.Date(2026, 6, 10, 19, 46, 0, 0, time.UTC)
	err := tokenExpiryError(TokenData{ExpiresAt: "2026-06-10T19:41:02.745964Z"}, now)
	if err == nil || !strings.Contains(err.Error(), "KAS token expired") {
		t.Fatalf("expired token error = %v, want KAS token expired", err)
	}
	if err := tokenExpiryError(TokenData{ExpiresAt: "2026-06-10T19:50:00Z"}, now); err != nil {
		t.Fatalf("future token error = %v, want nil", err)
	}
}

func TestShouldRefreshKASToken(t *testing.T) {
	now := time.Date(2026, 6, 10, 19, 46, 0, 0, time.UTC)
	if !shouldRefreshKASToken(TokenData{ExpiresAt: "2026-06-10T19:50:00Z"}, now) {
		t.Fatalf("token expiring within skew should refresh")
	}
	if shouldRefreshKASToken(TokenData{ExpiresAt: "2026-06-10T20:00:00Z"}, now) {
		t.Fatalf("token expiring later should not refresh")
	}
	if shouldRefreshKASToken(TokenData{}, now) {
		t.Fatalf("token without expiresAt should not refresh")
	}
}

func TestRefreshKASTokenPreservesAccountMetadata(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	credits := 49.85
	lastDuration := int64(123)
	account, err := writeTokenAccount("work", TokenData{
		AccessToken:        "old-access",
		RefreshToken:       "old-refresh",
		ExpiresAt:          "2026-06-10T19:41:02Z",
		ProfileArn:         "arn:old",
		APIKey:             "sk-old",
		Group:              "team-a",
		CreditsRemaining:   &credits,
		LastTestDurationMs: &lastDuration,
	})
	if err != nil {
		t.Fatalf("write account: %v", err)
	}

	oldRefresher := kasTokenRefresher
	kasTokenRefresher = func(TokenAccount) (TokenData, error) {
		return TokenData{
			AccessToken:  "new-access",
			RefreshToken: "new-refresh",
			ExpiresAt:    "2026-06-10T20:41:02Z",
			ProfileArn:   "arn:new",
		}, nil
	}
	defer func() { kasTokenRefresher = oldRefresher }()

	if err := refreshKASToken(account); err != nil {
		t.Fatalf("refresh token: %v", err)
	}

	selected, err := selectTokenAccount("work")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if selected.Token.AccessToken != "new-access" {
		t.Fatalf("access token = %q, want new-access", selected.Token.AccessToken)
	}
	if selected.Token.APIKey != "sk-old" {
		t.Fatalf("api key = %q, want sk-old", selected.Token.APIKey)
	}
	if selected.Token.Group != "team-a" {
		t.Fatalf("group = %q, want team-a", selected.Token.Group)
	}
	if selected.Token.RefreshToken != "new-refresh" {
		t.Fatalf("refresh token = %q, want new-refresh", selected.Token.RefreshToken)
	}
	if selected.Token.CreditsRemaining == nil || *selected.Token.CreditsRemaining != credits {
		t.Fatalf("credits were not preserved: %v", selected.Token.CreditsRemaining)
	}
	if selected.Token.LastTestDurationMs == nil || *selected.Token.LastTestDurationMs != lastDuration {
		t.Fatalf("last duration was not preserved: %v", selected.Token.LastTestDurationMs)
	}
}

func TestRefreshKASTokenFromStoredToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode refresh request: %v", err)
		}
		if req["refreshToken"] != "old-refresh" {
			t.Fatalf("refreshToken = %q, want old-refresh", req["refreshToken"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"new-access","refreshToken":"new-refresh","expiresIn":3600,"profileArn":"arn:test"}`))
	}))
	defer server.Close()

	oldEndpoint := kiroAuthRefreshEndpoint
	kiroAuthRefreshEndpoint = server.URL
	defer func() { kiroAuthRefreshEndpoint = oldEndpoint }()

	token, err := refreshKASTokenFromCommand(TokenAccount{
		Name: "work",
		Token: TokenData{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			ProfileArn:   "arn:test",
		},
	})
	if err != nil {
		t.Fatalf("refresh from stored token: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Fatalf("access token = %q, want new-access", token.AccessToken)
	}
	if token.RefreshToken != "new-refresh" {
		t.Fatalf("refresh token = %q, want new-refresh", token.RefreshToken)
	}
	if token.ExpiresAt == "" {
		t.Fatalf("expiresAt is empty")
	}
}

func TestRefreshKASTokenFromOIDCToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			t.Fatalf("path = %q, want /token", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content-type = %q, want application/json", got)
		}
		var req struct {
			ClientID     string   `json:"clientId"`
			ClientSecret string   `json:"clientSecret"`
			GrantType    string   `json:"grantType"`
			RefreshToken string   `json:"refreshToken"`
			Scope        []string `json:"scope"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode refresh request: %v", err)
		}
		if req.ClientID != "client-id" || req.ClientSecret != "client-secret" {
			t.Fatalf("client registration = %+v", req)
		}
		if req.GrantType != "refresh_token" || req.RefreshToken != "old-refresh" {
			t.Fatalf("grant request = %+v", req)
		}
		if len(req.Scope) != 1 || req.Scope[0] != "codewhisperer:completions" {
			t.Fatalf("scope = %+v", req.Scope)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"new-access","refreshToken":"new-refresh","expiresIn":3600,"tokenType":"Bearer"}`))
	}))
	defer server.Close()

	oldEndpoint := kiroOIDCTokenEndpoint
	kiroOIDCTokenEndpoint = server.URL + "/token"
	defer func() { kiroOIDCTokenEndpoint = oldEndpoint }()

	token, err := refreshKASTokenFromCommand(TokenAccount{
		Name: "builder",
		Token: TokenData{
			AccessToken:        "old-access",
			RefreshToken:       "old-refresh",
			ExpiresAt:          "2026-06-10T19:41:02Z",
			Region:             "us-east-1",
			StartURL:           "https://view.awsapps.com/start",
			OAuthFlow:          "PKCE",
			Scopes:             []string{"codewhisperer:completions"},
			ClientID:           "client-id",
			ClientSecret:       "client-secret",
			ClientSecretExpiry: "2026-12-31T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("refresh OIDC token: %v", err)
	}
	if token.AccessToken != "new-access" || token.RefreshToken != "new-refresh" {
		t.Fatalf("token = %+v", token)
	}
	if token.ExpiresAt == "" {
		t.Fatalf("expiresAt is empty")
	}
}

func TestRefreshKASTokenFromOIDCTokenRequiresClientRegistration(t *testing.T) {
	_, err := refreshKASTokenFromCommand(TokenAccount{
		Name: "builder",
		Token: TokenData{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			OAuthFlow:    "PKCE",
		},
	})
	if err == nil {
		t.Fatal("refresh error is nil")
	}
	if !strings.Contains(err.Error(), "clientId/clientSecret") {
		t.Fatalf("error = %q, want clientId/clientSecret", err)
	}
}

func TestRefreshKASTokenFromStoredTokenReturnsDirectRefreshError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad refresh", http.StatusUnauthorized)
	}))
	defer server.Close()

	oldEndpoint := kiroAuthRefreshEndpoint
	kiroAuthRefreshEndpoint = server.URL
	defer func() { kiroAuthRefreshEndpoint = oldEndpoint }()

	_, err := refreshKASTokenFromCommand(TokenAccount{
		Name: "work",
		Token: TokenData{
			RefreshToken: "old-refresh",
			ProfileArn:   "arn:test",
		},
	})
	if err == nil {
		t.Fatal("refresh error is nil")
	}
	if !strings.Contains(err.Error(), "kiro refresh status: 401") {
		t.Fatalf("error = %q, want direct refresh error", err)
	}
	if strings.Contains(err.Error(), "SQLite") {
		t.Fatalf("error = %q, want no SQLite fallback", err)
	}
}

func TestRefreshKASTokenFromCommandRequiresRefreshToken(t *testing.T) {
	_, err := refreshKASTokenFromCommand(TokenAccount{Name: "work"})
	if err == nil {
		t.Fatal("refresh error is nil")
	}
	if !strings.Contains(err.Error(), "missing refreshToken") {
		t.Fatalf("error = %q, want missing refreshToken", err)
	}
}

func TestRefreshCreditsForAccountNameSavesCredits(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	const profileArn = "arn:aws:codewhisperer:us-east-1:699475941385:profile/test"
	if _, err := writeTokenAccount("work", TokenData{
		AccessToken:  "kas-access",
		RefreshToken: "kas-refresh",
		ProfileArn:   profileArn,
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got := r.Header.Get("Authorization"); got != "Bearer kas-access" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("X-Amz-Target"); got != "AmazonCodeWhispererService.GetUsageLimits" {
			t.Fatalf("target = %q", got)
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode usage request: %v", err)
		}
		if req["profileArn"] != profileArn {
			t.Fatalf("profileArn = %q, want %q", req["profileArn"], profileArn)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		_, _ = w.Write([]byte(`{"usageBreakdownList":[{"resourceType":"CREDIT","currentUsageWithPrecision":0.26,"usageLimitWithPrecision":50.0}]}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererUsageEndpoint
	codeWhispererUsageEndpoint = server.URL
	defer func() { codeWhispererUsageEndpoint = oldEndpoint }()

	if err := refreshCreditsForAccountName("work"); err != nil {
		t.Fatalf("refresh credits: %v", err)
	}
	if !called {
		t.Fatalf("usage endpoint was not called")
	}

	selected, err := selectTokenAccount("work")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if selected.Token.CreditsRemaining == nil || *selected.Token.CreditsRemaining < 49.739 || *selected.Token.CreditsRemaining > 49.741 {
		t.Fatalf("stored credits = %v, want 49.74", selected.Token.CreditsRemaining)
	}
}

func TestRefreshCreditsWithoutProfileArnSendsEmptyBody(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := writeTokenAccount("builder", TokenData{
		AccessToken:  "kas-access",
		RefreshToken: "kas-refresh",
		OAuthFlow:    "PKCE",
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode usage request: %v", err)
		}
		if _, ok := req["profileArn"]; ok {
			t.Fatalf("usage request should not include profileArn: %+v", req)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		_, _ = w.Write([]byte(`{"usageBreakdownList":[{"resourceType":"CREDIT","currentUsageWithPrecision":2,"usageLimitWithPrecision":50}]}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererUsageEndpoint
	codeWhispererUsageEndpoint = server.URL
	defer func() { codeWhispererUsageEndpoint = oldEndpoint }()

	if err := refreshCreditsForAccountName("builder"); err != nil {
		t.Fatalf("refresh credits: %v", err)
	}

	selected, err := selectTokenAccount("builder")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if selected.Token.CreditsRemaining == nil || *selected.Token.CreditsRemaining != 48 {
		t.Fatalf("stored credits = %v, want 48", selected.Token.CreditsRemaining)
	}
}

func TestHandleAdminAccountCreditsRefreshesCredits(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := writeTokenAccount("work", TokenData{
		AccessToken:  "kas-access",
		RefreshToken: "kas-refresh",
		ProfileArn:   "arn:aws:codewhisperer:us-east-1:699475941385:profile/test",
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		_, _ = w.Write([]byte(`{"usageBreakdownList":[{"resourceType":"CREDIT","currentUsageWithPrecision":1,"usageLimitWithPrecision":50}]}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererUsageEndpoint
	codeWhispererUsageEndpoint = server.URL
	defer func() { codeWhispererUsageEndpoint = oldEndpoint }()

	rr := httptest.NewRecorder()
	handleAdminAccountAction(rr, httptest.NewRequest(http.MethodPost, "/admin/api/accounts/work/credits", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp AccountInfo
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CreditsRemaining == nil || *resp.CreditsRemaining != 49 {
		t.Fatalf("credits = %v, want 49", resp.CreditsRemaining)
	}
}

func TestHandleAdminAccountCheckStoresBlockedAccountStatus(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	credits := 50.0
	if _, err := writeTokenAccount("builder", TokenData{
		AccessToken:      "kas-access",
		RefreshToken:     "kas-refresh",
		CreditsRemaining: &credits,
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","message":"Your User ID temporarily is suspended. We've locked your account as a security precaution."}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererGenerateEndpoint
	codeWhispererGenerateEndpoint = server.URL
	defer func() { codeWhispererGenerateEndpoint = oldEndpoint }()

	rr := httptest.NewRecorder()
	handleAdminAccountAction(rr, httptest.NewRequest(http.MethodPost, "/admin/api/accounts/builder/check", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var result map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result["ok"] != false || !strings.Contains(fmt.Sprint(result["message"]), "заблокирован") {
		t.Fatalf("result = %+v, want blocked account message", result)
	}

	account, err := selectTokenAccount("builder")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if !account.Token.Disabled {
		t.Fatal("blocked account should be disabled")
	}
	info := tokenAccountInfo(account, "")
	if info.Status != "error" || !strings.Contains(info.StatusMessage, "заблокирован") {
		t.Fatalf("status = %q %q, want blocked account", info.Status, info.StatusMessage)
	}
}

func TestHandleAdminAccountCheckDiagnosesGenericInvalidBearer(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	credits := 50.0
	if _, err := writeTokenAccount("builder", TokenData{
		AccessToken:      "kas-access",
		RefreshToken:     "kas-refresh",
		CreditsRemaining: &credits,
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	generateServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"The bearer token included in the request is invalid.","reason":null}`))
	}))
	defer generateServer.Close()

	modelsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","message":"Your User ID temporarily is suspended. We've locked your account as a security precaution."}`))
	}))
	defer modelsServer.Close()

	oldGenerateEndpoint := codeWhispererGenerateEndpoint
	oldModelsEndpoint := codeWhispererListModelsEndpoint
	codeWhispererGenerateEndpoint = generateServer.URL
	codeWhispererListModelsEndpoint = modelsServer.URL
	defer func() {
		codeWhispererGenerateEndpoint = oldGenerateEndpoint
		codeWhispererListModelsEndpoint = oldModelsEndpoint
	}()

	rr := httptest.NewRecorder()
	handleAdminAccountAction(rr, httptest.NewRequest(http.MethodPost, "/admin/api/accounts/builder/check", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	account, err := selectTokenAccount("builder")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if !account.Token.Disabled {
		t.Fatal("blocked account should be disabled")
	}
	info := tokenAccountInfo(account, "")
	if info.Status != "error" || !strings.Contains(info.StatusMessage, "заблокирован") {
		t.Fatalf("status = %q %q, want blocked account", info.Status, info.StatusMessage)
	}
}

func TestHandleNewAPITokenUsage(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := writeTokenAccount("work", TokenData{
		AccessToken:  "kas-access",
		RefreshToken: "kas-refresh",
		ExpiresAt:    "2030-06-10T22:51:18.575431342Z",
		ProfileArn:   "arn:aws:codewhisperer:us-east-1:699475941385:profile/test",
		APIKey:       "sk-test",
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		_, _ = w.Write([]byte(`{"usageBreakdownList":[{"resourceType":"CREDIT","currentUsageWithPrecision":0.5,"usageLimitWithPrecision":50}]}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererUsageEndpoint
	codeWhispererUsageEndpoint = server.URL
	defer func() { codeWhispererUsageEndpoint = oldEndpoint }()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/usage/token/", nil)
	req.Header.Set("Authorization", "Bearer sk-test")
	handleNewAPITokenUsage(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Code bool `json:"code"`
		Data struct {
			Object         string  `json:"object"`
			Name           string  `json:"name"`
			TotalAvailable float64 `json:"total_available"`
			ExpiresAt      int64   `json:"expires_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Code {
		t.Fatalf("code = false, want true")
	}
	if resp.Data.Object != "token_usage" || resp.Data.Name != "work" {
		t.Fatalf("data = %+v, want token_usage for work", resp.Data)
	}
	if resp.Data.TotalAvailable != 49.5 {
		t.Fatalf("total_available = %v, want 49.5", resp.Data.TotalAvailable)
	}
	if resp.Data.ExpiresAt != 1907362278 {
		t.Fatalf("expires_at = %d, want 1907362278", resp.Data.ExpiresAt)
	}
}

func TestHandleAdminUsageSkipsDisabledAccounts(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	enabledCredits := 12.0
	disabledCredits := 50.0
	if _, err := writeTokenAccount("enabled", TokenData{
		AccessToken:      "kas-enabled",
		RefreshToken:     "refresh",
		CreditsRemaining: &enabledCredits,
	}); err != nil {
		t.Fatalf("write enabled account: %v", err)
	}
	if _, err := writeTokenAccount("disabled", TokenData{
		AccessToken:      "kas-disabled",
		RefreshToken:     "refresh",
		CreditsRemaining: &disabledCredits,
		Disabled:         true,
	}); err != nil {
		t.Fatalf("write disabled account: %v", err)
	}

	rr := httptest.NewRecorder()
	handleAdminUsage(rr, httptest.NewRequest(http.MethodGet, "/admin/api/usage", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		CreditsRemaining float64 `json:"creditsRemaining"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CreditsRemaining != enabledCredits {
		t.Fatalf("creditsRemaining = %v, want %v", resp.CreditsRemaining, enabledCredits)
	}
}

func TestHandleNewAPITokenUsageRequiresAuthorization(t *testing.T) {
	rr := httptest.NewRecorder()
	handleNewAPITokenUsage(rr, httptest.NewRequest(http.MethodGet, "/api/usage/token/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestOpenAIBillingEndpoints(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := writeTokenAccount("work", TokenData{
		AccessToken:  "kas-access",
		RefreshToken: "kas-refresh",
		ExpiresAt:    "2030-06-10T22:51:18Z",
		ProfileArn:   "arn:aws:codewhisperer:us-east-1:699475941385:profile/test",
		APIKey:       "sk-test",
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		_, _ = w.Write([]byte(`{"usageBreakdownList":[{"resourceType":"CREDIT","currentUsageWithPrecision":1.5,"usageLimitWithPrecision":50}]}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererUsageEndpoint
	codeWhispererUsageEndpoint = server.URL
	defer func() { codeWhispererUsageEndpoint = oldEndpoint }()

	t.Run("subscription", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/billing/subscription", nil)
		req.Header.Set("Authorization", "Bearer sk-test")
		handleOpenAISubscription(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Object       string  `json:"object"`
			HardLimitUSD float64 `json:"hard_limit_usd"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.Object != "billing_subscription" || resp.HardLimitUSD != 48.5 {
			t.Fatalf("response = %+v, want subscription with 48.5", resp)
		}
	})

	t.Run("usage", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/billing/usage", nil)
		req.Header.Set("Authorization", "Bearer sk-test")
		handleOpenAIUsage(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Object     string  `json:"object"`
			TotalUsage float64 `json:"total_usage"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.Object != "list" || resp.TotalUsage != 0 {
			t.Fatalf("response = %+v, want zero usage list", resp)
		}
	})

	t.Run("credit grants", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/dashboard/billing/credit_grants", nil)
		req.Header.Set("Authorization", "Bearer sk-test")
		handleOpenAICreditGrants(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			TotalAvailable float64 `json:"total_available"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.TotalAvailable != 48.5 {
			t.Fatalf("total_available = %v, want 48.5", resp.TotalAvailable)
		}
	})

	t.Run("v1 credit grants", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/billing/credit_grants", nil)
		req.Header.Set("Authorization", "Bearer sk-test")
		handleOpenAICreditGrants(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			TotalAvailable float64 `json:"total_available"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.TotalAvailable != 48.5 {
			t.Fatalf("total_available = %v, want 48.5", resp.TotalAvailable)
		}
	})
}

func TestHandleAdminConfigReportsBalanceSupport(t *testing.T) {
	rr := httptest.NewRecorder()
	handleAdminConfig(rr, httptest.NewRequest(http.MethodGet, "/admin/api/config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		BalanceSupport bool   `json:"balanceSupport"`
		GlobalAPIKey   string `json:"globalApiKey"`
		GroupKeys      []any  `json:"groupKeys"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.BalanceSupport {
		t.Fatalf("balanceSupport = false, want true")
	}
	if resp.GlobalAPIKey != "" {
		t.Fatalf("globalApiKey = %q, want empty", resp.GlobalAPIKey)
	}
	if len(resp.GroupKeys) == 0 {
		t.Fatalf("groupKeys is empty")
	}
}

func TestHandleModels(t *testing.T) {
	rr := httptest.NewRecorder()
	handleModels(rr, httptest.NewRequest(http.MethodGet, "/models", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Object string `json:"object"`
		Data   []struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Object != "list" {
		t.Fatalf("object = %q, want list", resp.Object)
	}
	if len(resp.Data) != len(fallbackModels()) {
		t.Fatalf("models len = %d, want %d", len(resp.Data), len(fallbackModels()))
	}
	hasAuto := false
	for _, model := range resp.Data {
		if model.Object != "model" || model.OwnedBy != "kiro2cc" {
			t.Fatalf("model = %+v", model)
		}
		if model.ID == "auto" {
			hasAuto = true
		}
	}
	if !hasAuto {
		t.Fatalf("auto model is missing")
	}
}

func TestHandleModelsFetchesAvailableModelsByAPIKey(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := writeTokenAccount("work", TokenData{
		AccessToken:  "kas-access",
		RefreshToken: "kas-refresh",
		ExpiresAt:    "2030-06-10T22:51:18Z",
		ProfileArn:   "arn:test",
		APIKey:       "sk-test",
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer kas-access" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("X-Amz-Target"); got != "AmazonCodeWhispererService.ListAvailableModels" {
			t.Fatalf("target = %q", got)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		_, _ = w.Write([]byte(`{"models":[{"modelId":"auto","modelName":"Auto","description":"Models chosen by task","rateMultiplier":1,"rateUnit":"Credit"},{"modelId":"claude-sonnet-4.5","modelName":"Claude Sonnet 4.5","description":"The Claude Sonnet 4.5 model","rateMultiplier":1.3,"rateUnit":"Credit"}]}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererListModelsEndpoint
	codeWhispererListModelsEndpoint = server.URL
	defer func() { codeWhispererListModelsEndpoint = oldEndpoint }()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("x-api-key", "sk-test")
	handleModels(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data []struct {
			ID             string  `json:"id"`
			RateMultiplier float64 `json:"rate_multiplier"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 2 {
		t.Fatalf("models len = %d, want 2", len(resp.Data))
	}
	if resp.Data[1].ID != "claude-sonnet-4.5" || resp.Data[1].RateMultiplier != 1.3 {
		t.Fatalf("model = %+v, want claude-sonnet-4.5 with multiplier", resp.Data[1])
	}
}

func TestHandleAdminHistoryDeleteClearsRequests(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	clearRequestHistory()
	addRequestHistory(RequestLogEntry{ID: "req", Time: "2026-06-16T10:00:00Z", Status: http.StatusOK})
	rr := httptest.NewRecorder()
	handleAdminHistory(rr, httptest.NewRequest(http.MethodDelete, "/admin/api/history", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if got := getRequestHistory(); len(got) != 0 {
		t.Fatalf("history len = %d, want 0", len(got))
	}
}

func TestHandleAdminStatsResetKeepsHistory(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	clearRequestHistory()
	oldNow := nowFunc
	nowFunc = func() time.Time {
		return time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	}
	defer func() { nowFunc = oldNow }()

	addRequestHistory(RequestLogEntry{ID: "req", Time: "2026-06-16T10:00:00Z", Status: http.StatusOK})
	rr := httptest.NewRecorder()
	handleAdminStatsReset(rr, httptest.NewRequest(http.MethodPost, "/admin/api/stats/reset", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if got := getRequestHistory(); len(got) != 1 {
		t.Fatalf("history len = %d, want 1", len(got))
	}
	settings := loadAdminSettings()
	if settings.StatsResetAt != "2026-06-16T12:00:00Z" {
		t.Fatalf("statsResetAt = %q", settings.StatsResetAt)
	}
}

func TestAdminSettingsEnsureDefaultGroupKey(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := ensureAdminSettings(); err != nil {
		t.Fatalf("ensure settings: %v", err)
	}
	loaded := loadAdminSettings()
	if len(loaded.Groups) != 1 || loaded.Groups[0].Name != defaultAccountGroup {
		t.Fatalf("groups = %+v, want default group", loaded.Groups)
	}
	if !strings.HasPrefix(loaded.Groups[0].APIKey, "sk-") {
		t.Fatalf("default group key = %q, want sk-*", loaded.Groups[0].APIKey)
	}
}

func TestAdminSettingsResponseDoesNotExposeGlobalAPIKey(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	settings, err := ensureAdminSettings()
	if err != nil {
		t.Fatalf("ensure settings: %v", err)
	}
	data, err := json.Marshal(adminSettingsResponse(settings))
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if strings.Contains(string(data), "globalApiKey") {
		t.Fatalf("settings response exposes globalApiKey: %s", string(data))
	}
}

func TestHandleAdminAccountCheckSavesLastTestDuration(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_TOKEN_FILE", filepath.Join(tokenDir, defaultTokenFileName))

	if _, err := writeTokenAccount("work", TokenData{
		AccessToken:  "kas-access",
		RefreshToken: "kas-refresh",
		ProfileArn:   "arn:aws:codewhisperer:us-east-1:699475941385:profile/test",
	}); err != nil {
		t.Fatalf("write account: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer kas-access" {
			t.Fatalf("authorization = %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	oldEndpoint := codeWhispererGenerateEndpoint
	codeWhispererGenerateEndpoint = server.URL
	defer func() { codeWhispererGenerateEndpoint = oldEndpoint }()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/accounts/work/check", nil)
	handleAdminAccountAction(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := resp["lastTestDurationMs"]; !ok {
		t.Fatalf("lastTestDurationMs missing in response: %v", resp)
	}

	selected, err := selectTokenAccount("work")
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if selected.Token.LastTestDurationMs == nil {
		t.Fatalf("last test duration was not saved")
	}
}

func TestAdminAuthMiddlewareRequiresSession(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_ADMIN_PASSWORD", "secret-password")

	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	handler(rr, httptest.NewRequest(http.MethodGet, "/admin/api/accounts", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if called {
		t.Fatalf("handler was called without session")
	}
}

func TestAdminLoginSetsSessionCookie(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_ADMIN_PASSWORD", "secret-password")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader("password=secret-password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}
	if rr.Result().Cookies()[0].Name != adminSessionCookie {
		t.Fatalf("session cookie was not set")
	}
}

func TestHandleAdminPasswordResetReturnsToEnvPassword(t *testing.T) {
	tokenDir := t.TempDir()
	t.Setenv("KIRO2CC_TOKEN_DIR", tokenDir)
	t.Setenv("KIRO2CC_ADMIN_PASSWORD", "env-password")

	hash, err := hashAdminPassword("custom-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := saveAdminSettings(AdminSettings{
		AdminPasswordHash: hash,
	}); err != nil {
		t.Fatalf("save settings: %v", err)
	}

	body := bytes.NewBufferString(`{"currentPassword":"custom-password"}`)
	rr := httptest.NewRecorder()
	handleAdminPasswordReset(rr, httptest.NewRequest(http.MethodPost, "/admin/api/password/reset", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	settings := loadAdminSettings()
	if settings.AdminPasswordHash != "" {
		t.Fatalf("password hash = %q, want empty after reset", settings.AdminPasswordHash)
	}
	if !verifyAdminPassword("env-password") {
		t.Fatalf("env password should be valid after reset")
	}
	if verifyAdminPassword("custom-password") {
		t.Fatalf("custom password should not be valid after reset")
	}
}
