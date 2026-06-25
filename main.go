package main

import (
	"bytes"
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	jsonStr "encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/artemk1337/kiro-admin/parser"
)

// TokenData 表示token文件的结构
type TokenData struct {
	AccessToken        string   `json:"accessToken"`
	RefreshToken       string   `json:"refreshToken,omitempty"`
	ExpiresAt          string   `json:"expiresAt,omitempty"`
	ProfileArn         string   `json:"profileArn,omitempty"`
	Region             string   `json:"region,omitempty"`
	StartURL           string   `json:"startUrl,omitempty"`
	OAuthFlow          string   `json:"oauthFlow,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	ClientID           string   `json:"clientId,omitempty"`
	ClientSecret       string   `json:"clientSecret,omitempty"`
	ClientSecretExpiry string   `json:"clientSecretExpiresAt,omitempty"`
	APIKey             string   `json:"apiKey,omitempty"`
	Group              string   `json:"group,omitempty"`
	Disabled           bool     `json:"disabled,omitempty"`
	RPS                float64  `json:"rps,omitempty"`
	Concurrency        int      `json:"concurrency,omitempty"`
	CreditsRemaining   *float64 `json:"creditsRemaining,omitempty"`
	LastTestDurationMs *int64   `json:"lastTestDurationMs,omitempty"`
	LastCheckError     string   `json:"lastCheckError,omitempty"`
}

type TokenAccount struct {
	Name  string    `json:"name"`
	Path  string    `json:"path"`
	Token TokenData `json:"-"`
}

type AccountInfo struct {
	Name                string   `json:"name"`
	Path                string   `json:"path"`
	ExpiresAt           string   `json:"expiresAt,omitempty"`
	Active              bool     `json:"active"`
	HasAccessToken      bool     `json:"hasAccessToken"`
	HasProfileArn       bool     `json:"hasProfileArn"`
	AccessTokenPreview  string   `json:"accessTokenPreview,omitempty"`
	ProfileArn          string   `json:"profileArn,omitempty"`
	APIKey              string   `json:"apiKey,omitempty"`
	APIKeyPreview       string   `json:"apiKeyPreview,omitempty"`
	Group               string   `json:"group"`
	Enabled             bool     `json:"enabled"`
	Status              string   `json:"status"`
	StatusMessage       string   `json:"statusMessage"`
	RPS                 float64  `json:"rps"`
	Concurrency         int      `json:"concurrency"`
	CreditsRemaining    *float64 `json:"creditsRemaining,omitempty"`
	CreditsRefreshError string   `json:"creditsRefreshError,omitempty"`
	TokenRefreshError   string   `json:"tokenRefreshError,omitempty"`
	LastTestDurationMs  *int64   `json:"lastTestDurationMs,omitempty"`
	LastCheckError      string   `json:"lastCheckError,omitempty"`
}

type SaveAccountRequest struct {
	Name               string   `json:"name"`
	AccessToken        string   `json:"accessToken"`
	RefreshToken       string   `json:"refreshToken,omitempty"`
	ExpiresAt          string   `json:"expiresAt,omitempty"`
	ProfileArn         string   `json:"profileArn,omitempty"`
	Region             string   `json:"region,omitempty"`
	StartURL           string   `json:"startUrl,omitempty"`
	OAuthFlow          string   `json:"oauthFlow,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	ClientID           string   `json:"clientId,omitempty"`
	ClientSecret       string   `json:"clientSecret,omitempty"`
	ClientSecretExpiry string   `json:"clientSecretExpiresAt,omitempty"`
	APIKey             string   `json:"apiKey,omitempty"`
	Group              string   `json:"group,omitempty"`
	Enabled            *bool    `json:"enabled,omitempty"`
	RPS                float64  `json:"rps,omitempty"`
	Concurrency        int      `json:"concurrency,omitempty"`
	CreditsRemaining   *float64 `json:"creditsRemaining,omitempty"`
	LastTestDurationMs *int64   `json:"lastTestDurationMs,omitempty"`
	LastCheckError     string   `json:"lastCheckError,omitempty"`
}

type RequestLogEntry struct {
	ID           string   `json:"id"`
	Time         string   `json:"time"`
	Account      string   `json:"account"`
	APIKey       string   `json:"apiKey,omitempty"`
	Model        string   `json:"model,omitempty"`
	Stream       bool     `json:"stream"`
	Status       int      `json:"status"`
	DurationMs   int64    `json:"durationMs"`
	InputTokens  int      `json:"inputTokens,omitempty"`
	OutputTokens int      `json:"outputTokens,omitempty"`
	CreditsSpent *float64 `json:"creditsSpent,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type RequestStats struct {
	Total        int                   `json:"total"`
	Success      int                   `json:"success"`
	Failed       int                   `json:"failed"`
	StatusCounts map[string]int        `json:"statusCounts"`
	ErrorCounts  map[string]int        `json:"errorCounts"`
	Accounts     []AccountRequestStats `json:"accounts"`
}

type AccountRequestStats struct {
	Name        string  `json:"name"`
	Total       int     `json:"total"`
	Success     int     `json:"success"`
	Failed      int     `json:"failed"`
	FailureRate float64 `json:"failureRate"`
	AvgDuration int64   `json:"avgDurationMs"`
	LastError   string  `json:"lastError,omitempty"`
}

type AdminSettings struct {
	AdminPasswordHash string         `json:"adminPasswordHash,omitempty"`
	Groups            []AccountGroup `json:"groups,omitempty"`
	StatsResetAt      string         `json:"statsResetAt,omitempty"`
}

type AccountGroup struct {
	Name   string `json:"name"`
	APIKey string `json:"apiKey"`
}

type AccountGroupInfo struct {
	Name          string   `json:"name"`
	APIKey        string   `json:"apiKey"`
	APIKeyPreview string   `json:"apiKeyPreview"`
	Accounts      int      `json:"accounts"`
	Enabled       int      `json:"enabled"`
	Credits       *float64 `json:"creditsRemaining,omitempty"`
}

type AdminSettingsResponse struct {
	Groups          []AccountGroupInfo `json:"groups"`
	StatsResetAt    string             `json:"statsResetAt,omitempty"`
	HasPassword     bool               `json:"hasPassword"`
	UsesEnvPassword bool               `json:"usesEnvPassword"`
}

type AdminPasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type KiroRefreshResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int64  `json:"expiresIn"`
	ProfileArn   string `json:"profileArn"`
}

type KiroOIDCRefreshResponse struct {
	AccessToken  string `json:"accessToken"`
	ExpiresIn    int64  `json:"expiresIn"`
	RefreshToken string `json:"refreshToken"`
	TokenType    string `json:"tokenType"`
}

type KiroOIDCRegisterResponse struct {
	AuthorizationEndpoint  string `json:"authorizationEndpoint"`
	ClientID               string `json:"clientId"`
	ClientSecret           string `json:"clientSecret"`
	ClientSecretExpiresAt  int64  `json:"clientSecretExpiresAt"`
	ClientSecretExpiresRFC string `json:"-"`
	TokenEndpoint          string `json:"tokenEndpoint"`
}

type KiroOIDCDeviceAuthorizationResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int64  `json:"expiresIn"`
	Interval                int64  `json:"interval"`
	Region                  string `json:"region"`
	StartURL                string `json:"startUrl"`
}

type KiroOIDCLoginSession struct {
	ID             string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastPollAt     time.Time
	Registration   KiroOIDCRegisterResponse
	Authorization  KiroOIDCDeviceAuthorizationResponse
	CompletedToken *TokenData
	LastError      string
}

const (
	defaultTokenFileName      = "kas-token.json"
	maxRequestHistory         = 1000
	historyFileName           = "request-history.json"
	settingsFileName          = "admin-settings.json"
	adminSessionCookie        = "kiro-admin_admin_session"
	adminSessionTTL           = 24 * time.Hour
	outboundHTTPTimeout       = 5 * time.Minute
	tokenRefreshInterval      = time.Minute
	tokenRefreshSkew          = 5 * time.Minute
	defaultAccountRPS         = 2.0
	defaultAccountConcurrency = 4
	defaultAccountGroup       = "default"
	defaultProfileArn         = "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK"
	kiroOIDCRegion            = "us-east-1"
	kiroOIDCStartURL          = "https://view.awsapps.com/start"
	kiroOIDCClientName        = "Kiro CLI"
	kiroOIDCClientType        = "public"
	kiroOIDCDeviceGrantType   = "urn:ietf:params:oauth:grant-type:device_code"
	kiroOIDCAuthSessionTTL    = 10 * time.Minute
)

var kiroOIDCScopes = []string{
	"codewhisperer:completions",
	"codewhisperer:analysis",
	"codewhisperer:conversations",
}

var requestHistory struct {
	sync.Mutex
	entries []RequestLogEntry
}

type accountLimiterState struct {
	inFlight int
	starts   []time.Time
}

var accountLimiters struct {
	sync.Mutex
	byName map[string]*accountLimiterState
}

var nowFunc = time.Now

var kiroAuthRefreshEndpoint = "https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken"
var kiroOIDCRegisterEndpoint = "https://oidc.%s.amazonaws.com/client/register"
var kiroOIDCDeviceAuthEndpoint = "https://oidc.%s.amazonaws.com/device_authorization"
var kiroOIDCTokenEndpoint = "https://oidc.%s.amazonaws.com/token"
var codeWhispererGenerateEndpoint = "https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse"
var codeWhispererUsageEndpoint = "https://codewhisperer.us-east-1.amazonaws.com/"
var codeWhispererListModelsEndpoint = "https://codewhisperer.us-east-1.amazonaws.com/"
var kasTokenRefresher = refreshKASTokenFromCommand

var oidcLoginSessions struct {
	sync.Mutex
	byID map[string]*KiroOIDCLoginSession
}

func newOutboundHTTPClient() *http.Client {
	return &http.Client{Timeout: outboundHTTPTimeout}
}

// AnthropicTool 表示 Anthropic API 的工具结构
type AnthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// InputSchema 表示工具输入模式的结构
type InputSchema struct {
	Json map[string]any `json:"json"`
}

// ToolSpecification 表示工具规范的结构
type ToolSpecification struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// CodeWhispererTool 表示 CodeWhisperer API 的工具结构
type CodeWhispererTool struct {
	ToolSpecification ToolSpecification `json:"toolSpecification"`
}

// HistoryUserMessage 表示历史记录中的用户消息
type HistoryUserMessage struct {
	UserInputMessage struct {
		Content string `json:"content"`
		ModelId string `json:"modelId"`
		Origin  string `json:"origin"`
	} `json:"userInputMessage"`
}

// HistoryAssistantMessage 表示历史记录中的助手消息
type HistoryAssistantMessage struct {
	AssistantResponseMessage struct {
		Content  string `json:"content"`
		ToolUses []any  `json:"toolUses"`
	} `json:"assistantResponseMessage"`
}

// AnthropicRequest 表示 Anthropic API 的请求结构
type AnthropicRequest struct {
	Model       string                    `json:"model"`
	MaxTokens   int                       `json:"max_tokens"`
	Messages    []AnthropicRequestMessage `json:"messages"`
	System      []AnthropicSystemMessage  `json:"system,omitempty"`
	Tools       []AnthropicTool           `json:"tools,omitempty"`
	Stream      bool                      `json:"stream"`
	Temperature *float64                  `json:"temperature,omitempty"`
	Metadata    map[string]any            `json:"metadata,omitempty"`
}

// AnthropicStreamResponse 表示 Anthropic 流式响应的结构
type AnthropicStreamResponse struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentDelta struct {
		Text string `json:"text"`
		Type string `json:"type"`
	} `json:"delta,omitempty"`
	Content []struct {
		Text string `json:"text"`
		Type string `json:"type"`
	} `json:"content,omitempty"`
	StopReason   string `json:"stop_reason,omitempty"`
	StopSequence string `json:"stop_sequence,omitempty"`
	Usage        struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage,omitempty"`
}

// AnthropicRequestMessage 表示 Anthropic API 的消息结构
type AnthropicRequestMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // 可以是 string 或 []ContentBlock
}

type AnthropicSystemMessage struct {
	Type string `json:"type"`
	Text string `json:"text"` // 可以是 string 或 []ContentBlock
}

type OpenAIChatCompletionRequest struct {
	Model       string              `json:"model"`
	Messages    []OpenAIChatMessage `json:"messages"`
	Stream      bool                `json:"stream"`
	MaxTokens   int                 `json:"max_tokens,omitempty"`
	Temperature *float64            `json:"temperature,omitempty"`
	Tools       []OpenAIChatTool    `json:"tools,omitempty"`
}

type OpenAIChatMessage struct {
	Role       string           `json:"role"`
	Content    any              `json:"content,omitempty"`
	ToolCalls  []OpenAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	Name       string           `json:"name,omitempty"`
}

type OpenAIChatTool struct {
	Type     string             `json:"type"`
	Function OpenAIChatFunction `json:"function"`
}

type OpenAIChatFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	Arguments   string         `json:"arguments,omitempty"`
}

type OpenAIToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function OpenAIChatFunction `json:"function"`
}

type anthropicMessageResponse struct {
	Content []struct {
		Type  string         `json:"type"`
		Text  string         `json:"text,omitempty"`
		ID    string         `json:"id,omitempty"`
		Name  string         `json:"name,omitempty"`
		Input map[string]any `json:"input,omitempty"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ContentBlock 表示消息内容块的结构
type ContentBlock struct {
	Type      string  `json:"type"`
	Text      *string `json:"text,omitempty"`
	ToolUseId *string `json:"tool_use_id,omitempty"`
	Content   *string `json:"content,omitempty"`
	Name      *string `json:"name,omitempty"`
	Input     *any    `json:"input,omitempty"`
}

// getMessageContent 从消息中提取文本内容
func getMessageContent(content any) string {
	switch v := content.(type) {
	case string:
		if len(v) == 0 {
			return "answer for user qeustion"
		}
		return v
	case []interface{}:
		var texts []string
		for _, block := range v {

			if m, ok := block.(map[string]interface{}); ok {
				var cb ContentBlock
				if data, err := jsonStr.Marshal(m); err == nil {
					if err := jsonStr.Unmarshal(data, &cb); err == nil {
						switch cb.Type {
						case "tool_result":
							texts = append(texts, *cb.Content)
						case "text":
							texts = append(texts, *cb.Text)
						}
					}

				}
			}

		}
		if len(texts) == 0 {
			s, err := jsonStr.Marshal(content)
			if err != nil {
				return "answer for user qeustion"
			}

			log.Printf("uncatch: %s", string(s))
			return "answer for user qeustion"
		}
		return strings.Join(texts, "\n")
	default:
		s, err := jsonStr.Marshal(content)
		if err != nil {
			return "answer for user qeustion"
		}

		log.Printf("uncatch: %s", string(s))
		return "answer for user qeustion"
	}
}

func getStreamDeltaText(data any) string {
	m, ok := data.(map[string]any)
	if !ok {
		return ""
	}
	delta, ok := m["delta"].(map[string]any)
	if !ok {
		return ""
	}
	text, _ := delta["text"].(string)
	return text
}

func openAIRequestToAnthropic(req OpenAIChatCompletionRequest) (AnthropicRequest, error) {
	anthropicReq := AnthropicRequest{
		Model:       req.Model,
		MaxTokens:   req.MaxTokens,
		Stream:      req.Stream,
		Temperature: req.Temperature,
	}
	if anthropicReq.MaxTokens == 0 {
		anthropicReq.MaxTokens = 4096
	}

	for _, tool := range req.Tools {
		if tool.Type != "" && tool.Type != "function" {
			continue
		}
		anthropicReq.Tools = append(anthropicReq.Tools, AnthropicTool{
			Name:        tool.Function.Name,
			Description: tool.Function.Description,
			InputSchema: tool.Function.Parameters,
		})
	}

	for _, msg := range req.Messages {
		switch msg.Role {
		case "system":
			text := openAIContentText(msg.Content)
			if text != "" {
				anthropicReq.System = append(anthropicReq.System, AnthropicSystemMessage{Type: "text", Text: text})
			}
		case "user", "assistant":
			content := any(openAIContentText(msg.Content))
			if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
				content = openAIToolCallsToAnthropicContent(msg.ToolCalls)
			}
			anthropicReq.Messages = append(anthropicReq.Messages, AnthropicRequestMessage{
				Role:    msg.Role,
				Content: content,
			})
		case "tool":
			content := openAIContentText(msg.Content)
			anthropicReq.Messages = append(anthropicReq.Messages, AnthropicRequestMessage{
				Role: "user",
				Content: []map[string]any{{
					"type":        "tool_result",
					"tool_use_id": msg.ToolCallID,
					"content":     content,
				}},
			})
		}
	}

	if len(anthropicReq.Messages) == 0 {
		return AnthropicRequest{}, fmt.Errorf("messages must contain at least one user or assistant message")
	}
	if anthropicReq.Messages[len(anthropicReq.Messages)-1].Role != "user" {
		anthropicReq.Messages = append(anthropicReq.Messages, AnthropicRequestMessage{
			Role:    "user",
			Content: "continue",
		})
	}
	return anthropicReq, nil
}

func openAIContentText(content any) string {
	switch v := content.(type) {
	case nil:
		return ""
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			switch m["type"] {
			case "text":
				if text, ok := m["text"].(string); ok {
					parts = append(parts, text)
				}
			case "input_text":
				if text, ok := m["text"].(string); ok {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		data, err := jsonStr.Marshal(v)
		if err != nil {
			return ""
		}
		return string(data)
	}
}

func openAIToolCallsToAnthropicContent(toolCalls []OpenAIToolCall) []map[string]any {
	content := make([]map[string]any, 0, len(toolCalls))
	for _, call := range toolCalls {
		input := map[string]any{}
		if strings.TrimSpace(call.Function.Arguments) != "" {
			_ = jsonStr.Unmarshal([]byte(call.Function.Arguments), &input)
		}
		content = append(content, map[string]any{
			"type":  "tool_use",
			"id":    call.ID,
			"name":  call.Function.Name,
			"input": input,
		})
	}
	return content
}

func validateAnthropicRequest(req AnthropicRequest) error {
	if req.Model == "" {
		return fmt.Errorf("Missing required field: model")
	}
	if len(req.Messages) == 0 {
		return fmt.Errorf("Missing required field: messages")
	}
	if _, ok := ModelMap[req.Model]; !ok {
		available := make([]string, 0, len(ModelMap))
		for k := range ModelMap {
			available = append(available, k)
		}
		sort.Strings(available)
		return fmt.Errorf("Unknown or unsupported model: %s; availableModels: %s", req.Model, strings.Join(available, ","))
	}
	return nil
}

// CodeWhispererRequest 表示 CodeWhisperer API 的请求结构
type CodeWhispererRequest struct {
	ConversationState struct {
		ChatTriggerType string `json:"chatTriggerType"`
		ConversationId  string `json:"conversationId"`
		CurrentMessage  struct {
			UserInputMessage struct {
				Content                 string `json:"content"`
				ModelId                 string `json:"modelId"`
				Origin                  string `json:"origin"`
				UserInputMessageContext struct {
					ToolResults []struct {
						Content []struct {
							Text string `json:"text"`
						} `json:"content"`
						Status    string `json:"status"`
						ToolUseId string `json:"toolUseId"`
					} `json:"toolResults,omitempty"`
					Tools []CodeWhispererTool `json:"tools,omitempty"`
				} `json:"userInputMessageContext"`
			} `json:"userInputMessage"`
		} `json:"currentMessage"`
		History []any `json:"history"`
	} `json:"conversationState"`
	ProfileArn string `json:"profileArn"`
}

// CodeWhispererEvent 表示 CodeWhisperer 的事件响应
type CodeWhispererEvent struct {
	ContentType string `json:"content-type"`
	MessageType string `json:"message-type"`
	Content     string `json:"content"`
	EventType   string `json:"event-type"`
}

type CodeWhispererUsageResponse struct {
	UsageBreakdownList []CodeWhispererUsageBreakdown `json:"usageBreakdownList"`
}

type CodeWhispererUsageBreakdown struct {
	ResourceType              string  `json:"resourceType"`
	DisplayName               string  `json:"displayName"`
	CurrentUsage              int     `json:"currentUsage"`
	CurrentUsageWithPrecision float64 `json:"currentUsageWithPrecision"`
	UsageLimit                int     `json:"usageLimit"`
	UsageLimitWithPrecision   float64 `json:"usageLimitWithPrecision"`
}

type CodeWhispererModelsResponse struct {
	DefaultModel CodeWhispererModel   `json:"defaultModel"`
	Models       []CodeWhispererModel `json:"models"`
}

type CodeWhispererModel struct {
	ModelID        string  `json:"modelId"`
	ModelName      string  `json:"modelName"`
	Description    string  `json:"description"`
	RateMultiplier float64 `json:"rateMultiplier"`
	RateUnit       string  `json:"rateUnit"`
}

var ModelMap = map[string]string{
	"auto":                       "auto",
	"claude-sonnet-4.5":          "claude-sonnet-4.5",
	"claude-sonnet-4":            "claude-sonnet-4",
	"claude-haiku-4.5":           "claude-haiku-4.5",
	"deepseek-3.2":               "deepseek-3.2",
	"minimax-m2.5":               "minimax-m2.5",
	"minimax-m2.1":               "minimax-m2.1",
	"glm-5":                      "glm-5",
	"qwen3-coder-next":           "qwen3-coder-next",
	"claude-sonnet-4-20250514":   "claude-sonnet-4",
	"claude-3-7-sonnet-20250219": "claude-sonnet-4",
	"claude-3-5-haiku-20241022":  "claude-haiku-4.5",
}

// generateUUID generates a simple UUID v4
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant bits
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// buildCodeWhispererRequest 构建 CodeWhisperer 请求
func buildCodeWhispererRequest(anthropicReq AnthropicRequest, profileArn string) CodeWhispererRequest {
	profileArn = profileArnOrDefault(profileArn)

	cwReq := CodeWhispererRequest{
		ProfileArn: profileArn,
	}
	cwReq.ConversationState.ChatTriggerType = "MANUAL"
	cwReq.ConversationState.ConversationId = generateUUID()
	cwReq.ConversationState.CurrentMessage.UserInputMessage.Content = getMessageContent(anthropicReq.Messages[len(anthropicReq.Messages)-1].Content)
	cwReq.ConversationState.CurrentMessage.UserInputMessage.ModelId = ModelMap[anthropicReq.Model]
	cwReq.ConversationState.CurrentMessage.UserInputMessage.Origin = "AI_EDITOR"
	// 处理 tools 信息
	if len(anthropicReq.Tools) > 0 {
		var tools []CodeWhispererTool
		for _, tool := range anthropicReq.Tools {
			cwTool := CodeWhispererTool{}
			cwTool.ToolSpecification.Name = tool.Name
			cwTool.ToolSpecification.Description = tool.Description
			cwTool.ToolSpecification.InputSchema = InputSchema{
				Json: tool.InputSchema,
			}
			tools = append(tools, cwTool)
		}
		cwReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.Tools = tools
	}

	// 构建历史消息
	// 先处理 system 消息或者常规历史消息
	if len(anthropicReq.System) > 0 || len(anthropicReq.Messages) > 1 {
		var history []any

		// 首先添加每个 system 消息作为独立的历史记录项

		assistantDefaultMsg := HistoryAssistantMessage{}
		assistantDefaultMsg.AssistantResponseMessage.Content = getMessageContent("I will follow these instructions")
		assistantDefaultMsg.AssistantResponseMessage.ToolUses = make([]any, 0)

		if len(anthropicReq.System) > 0 {
			for _, sysMsg := range anthropicReq.System {
				userMsg := HistoryUserMessage{}
				userMsg.UserInputMessage.Content = sysMsg.Text
				userMsg.UserInputMessage.ModelId = ModelMap[anthropicReq.Model]
				userMsg.UserInputMessage.Origin = "AI_EDITOR"
				history = append(history, userMsg)
				history = append(history, assistantDefaultMsg)
			}
		}

		// 然后处理常规消息历史
		for i := 0; i < len(anthropicReq.Messages)-1; i++ {
			if anthropicReq.Messages[i].Role == "user" {
				userMsg := HistoryUserMessage{}
				userMsg.UserInputMessage.Content = getMessageContent(anthropicReq.Messages[i].Content)
				userMsg.UserInputMessage.ModelId = ModelMap[anthropicReq.Model]
				userMsg.UserInputMessage.Origin = "AI_EDITOR"
				history = append(history, userMsg)

				// 检查下一条消息是否是助手回复
				if i+1 < len(anthropicReq.Messages)-1 && anthropicReq.Messages[i+1].Role == "assistant" {
					assistantMsg := HistoryAssistantMessage{}
					assistantMsg.AssistantResponseMessage.Content = getMessageContent(anthropicReq.Messages[i+1].Content)
					assistantMsg.AssistantResponseMessage.ToolUses = make([]any, 0)
					history = append(history, assistantMsg)
					i++ // 跳过已处理的助手消息
				}
			}
		}

		cwReq.ConversationState.History = history
	}

	return cwReq
}

func profileArnOrDefault(profileArn string) string {
	profileArn = strings.TrimSpace(profileArn)
	if profileArn == "" {
		return defaultProfileArn
	}
	return profileArn
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法:")
		fmt.Println("  kiro-admin read    - 读取并显示token")
		fmt.Println("  kiro-admin export  - 导出环境变量")
		fmt.Println("  kiro-admin claude  - 跳过 claude 地区限制")
		fmt.Println("  kiro-admin server [port] - 启动Anthropic API代理服务器")
		fmt.Println("  author https://github.com/artemk1337/kiro-admin")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "read":
		readToken()
	case "export":
		exportEnvVars()

	case "claude":
		setClaude()
	case "server":
		port := "8080" // 默认端口
		if len(os.Args) > 2 {
			port = os.Args[2]
		}
		startServer(port)
	default:
		fmt.Printf("未知命令: %s\n", command)
		os.Exit(1)
	}
}

func getHomeDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("获取用户目录失败: %v\n", err)
		os.Exit(1)
	}

	return homeDir
}

// getTokenDir 获取token目录。Docker中通常设置为 /tokens。
func getTokenDir() string {
	if dir := strings.TrimSpace(os.Getenv("KIRO_ADMIN_TOKEN_DIR")); dir != "" {
		return dir
	}

	return filepath.Join(getHomeDir(), ".kiro-admin", "tokens")
}

// getTokenFilePath 获取跨平台的默认token文件路径
func getTokenFilePath() string {
	if path := strings.TrimSpace(os.Getenv("KIRO_ADMIN_TOKEN_FILE")); path != "" {
		return path
	}

	return filepath.Join(getTokenDir(), defaultTokenFileName)
}

func accountNameFromPath(path string) string {
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if name == "" {
		return "default"
	}
	return name
}

func sanitizeAccountName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".json")
	if name == "" {
		return ""
	}

	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), ".-")
}

func sanitizeGroupName(name string) string {
	name = sanitizeAccountName(name)
	if name == "" {
		return defaultAccountGroup
	}
	return name
}

func maskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 12 {
		return "***"
	}
	return token[:6] + "..." + token[len(token)-4:]
}

func generateAPIKey() string {
	return "sk-" + strings.ReplaceAll(generateUUID(), "-", "") + strings.ReplaceAll(generateUUID(), "-", "")[:16]
}

func normalizeTokenLimits(token *TokenData) {
	if token.RPS <= 0 {
		token.RPS = defaultAccountRPS
	}
	if token.Concurrency <= 0 {
		token.Concurrency = defaultAccountConcurrency
	}
}

func normalizeTokenGroup(token *TokenData) {
	token.Group = sanitizeGroupName(token.Group)
}

func normalizeTokenDefaults(token *TokenData) {
	normalizeTokenLimits(token)
	normalizeTokenGroup(token)
}

func tryAcquireAccountSlot(account TokenAccount) (func(), bool, time.Duration) {
	normalizeTokenLimits(&account.Token)
	now := time.Now()
	windowStart := now.Add(-time.Second)

	accountLimiters.Lock()
	defer accountLimiters.Unlock()

	if accountLimiters.byName == nil {
		accountLimiters.byName = map[string]*accountLimiterState{}
	}
	state := accountLimiters.byName[account.Name]
	if state == nil {
		state = &accountLimiterState{}
		accountLimiters.byName[account.Name] = state
	}

	kept := state.starts[:0]
	for _, startedAt := range state.starts {
		if startedAt.After(windowStart) {
			kept = append(kept, startedAt)
		}
	}
	state.starts = kept

	if state.inFlight >= account.Token.Concurrency {
		return nil, false, 100 * time.Millisecond
	}
	rpsLimit := int(account.Token.RPS)
	if rpsLimit < 1 {
		rpsLimit = 1
	}
	if len(state.starts) >= rpsLimit {
		retryAfter := time.Second - now.Sub(state.starts[0])
		if retryAfter < 100*time.Millisecond {
			retryAfter = 100 * time.Millisecond
		}
		return nil, false, retryAfter
	}

	state.inFlight++
	state.starts = append(state.starts, now)
	return func() {
		accountLimiters.Lock()
		defer accountLimiters.Unlock()
		if state.inFlight > 0 {
			state.inFlight--
		}
	}, true, 0
}

func loadTokenFromFile(path string) (TokenData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TokenData{}, fmt.Errorf("读取token文件失败: %v", err)
	}

	var token TokenData
	if err := jsonStr.Unmarshal(data, &token); err != nil {
		return TokenData{}, fmt.Errorf("解析token文件失败: %v", err)
	}
	if token.AccessToken == "" {
		return TokenData{}, fmt.Errorf("token文件缺少accessToken")
	}
	changed := false
	if token.APIKey == "" {
		token.APIKey = generateAPIKey()
		changed = true
	}
	beforeRPS, beforeConcurrency, beforeGroup := token.RPS, token.Concurrency, token.Group
	normalizeTokenDefaults(&token)
	if token.RPS != beforeRPS || token.Concurrency != beforeConcurrency || token.Group != beforeGroup {
		changed = true
	}
	if changed {
		if data, err := jsonStr.MarshalIndent(token, "", "  "); err == nil {
			_ = os.WriteFile(path, data, 0600)
		}
	}

	return token, nil
}

func listTokenAccounts() ([]TokenAccount, error) {
	paths := map[string]bool{}
	if path := getTokenFilePath(); path != "" {
		paths[path] = true
	}

	entries, err := os.ReadDir(getTokenDir())
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取token目录失败: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		paths[filepath.Join(getTokenDir(), entry.Name())] = true
	}

	accounts := make([]TokenAccount, 0, len(paths))
	for path := range paths {
		token, err := loadTokenFromFile(path)
		if err != nil {
			continue
		}
		accounts = append(accounts, TokenAccount{
			Name:  accountNameFromPath(path),
			Path:  path,
			Token: token,
		})
	}

	sort.Slice(accounts, func(i, j int) bool {
		if accounts[i].Path == getTokenFilePath() {
			return true
		}
		if accounts[j].Path == getTokenFilePath() {
			return false
		}
		return accounts[i].Name < accounts[j].Name
	})

	return accounts, nil
}

func selectTokenAccount(name string) (TokenAccount, error) {
	accounts, err := listTokenAccounts()
	if err != nil {
		return TokenAccount{}, err
	}
	if len(accounts) == 0 {
		return TokenAccount{}, fmt.Errorf("token аккаунты не найдены в %s", getTokenDir())
	}

	name = strings.TrimSpace(name)
	if name != "" {
		for _, account := range accounts {
			if account.Name == name {
				return account, nil
			}
		}
		return TokenAccount{}, fmt.Errorf("token аккаунт %q не найден", name)
	}

	return accounts[0], nil
}

func selectTokenAccountFromRequest(r *http.Request) (TokenAccount, error) {
	if key := requestAPIKey(r); strings.HasPrefix(key, "sk-") {
		if group, ok, err := selectAccountGroupByAPIKey(key); err != nil {
			return TokenAccount{}, err
		} else if ok {
			return TokenAccount{}, fmt.Errorf("group proxy key %s requires balanced endpoint handling", group.Name)
		}
		return selectTokenAccountByAPIKey(key)
	}
	if name := strings.TrimSpace(r.Header.Get("X-Kiro-Account")); name != "" {
		return selectTokenAccount(name)
	}
	return TokenAccount{}, fmt.Errorf("передайте x-api-key или Authorization: Bearer со значением sk-*")
}

func selectTokenAccountForRequest(r *http.Request, model string) (TokenAccount, func(), error) {
	if key := requestAPIKey(r); strings.HasPrefix(key, "sk-") {
		if group, ok, err := selectAccountGroupByAPIKey(key); err != nil {
			return TokenAccount{}, nil, err
		} else if ok {
			return selectBalancedTokenAccount(group.Name, model)
		}
		account, err := selectTokenAccountByAPIKey(key)
		if err != nil {
			return TokenAccount{}, nil, err
		}
		release, ok, retryAfter := tryAcquireAccountSlot(account)
		if !ok {
			return TokenAccount{}, nil, fmt.Errorf("account %s rate limited, retry after %s", account.Name, retryAfter.Round(time.Millisecond))
		}
		return account, release, nil
	}
	if name := strings.TrimSpace(r.Header.Get("X-Kiro-Account")); name != "" {
		account, err := selectTokenAccount(name)
		if err != nil {
			return TokenAccount{}, nil, err
		}
		release, ok, retryAfter := tryAcquireAccountSlot(account)
		if !ok {
			return TokenAccount{}, nil, fmt.Errorf("account %s rate limited, retry after %s", account.Name, retryAfter.Round(time.Millisecond))
		}
		return account, release, nil
	}
	return TokenAccount{}, nil, fmt.Errorf("передайте x-api-key или Authorization: Bearer со значением sk-*")
}

func selectAccountGroupByAPIKey(apiKey string) (AccountGroup, bool, error) {
	settings, err := ensureAdminSettings()
	if err != nil {
		return AccountGroup{}, false, err
	}
	for _, group := range settings.Groups {
		if group.APIKey == apiKey {
			return group, true, nil
		}
	}
	return AccountGroup{}, false, nil
}

func requestAPIKey(r *http.Request) string {
	if key := strings.TrimSpace(r.Header.Get("x-api-key")); key != "" {
		return key
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[len("Bearer "):])
	}
	return ""
}

func selectTokenAccountByAPIKey(apiKey string) (TokenAccount, error) {
	accounts, err := listTokenAccounts()
	if err != nil {
		return TokenAccount{}, err
	}
	for _, account := range accounts {
		if account.Token.APIKey == apiKey {
			return account, nil
		}
	}
	return TokenAccount{}, fmt.Errorf("proxy key не найден")
}

func selectBalancedTokenAccount(groupName, model string) (TokenAccount, func(), error) {
	accounts, err := listTokenAccounts()
	if err != nil {
		return TokenAccount{}, nil, err
	}
	groupName = sanitizeGroupName(groupName)
	groupAccounts := make([]TokenAccount, 0, len(accounts))
	for _, account := range accounts {
		if sanitizeGroupName(account.Token.Group) == groupName {
			groupAccounts = append(groupAccounts, account)
		}
	}
	accounts = groupAccounts
	if len(accounts) == 0 {
		return TokenAccount{}, nil, fmt.Errorf("token аккаунты не найдены в %s", getTokenDir())
	}

	sort.SliceStable(accounts, func(i, j int) bool {
		ai, aj := accounts[i].Token.CreditsRemaining, accounts[j].Token.CreditsRemaining
		if ai != nil && aj != nil && *ai != *aj {
			return *ai > *aj
		}
		if ai != nil && aj == nil {
			return true
		}
		if ai == nil && aj != nil {
			return false
		}
		return accounts[i].Name < accounts[j].Name
	})

	var lastErr error
	for _, account := range accounts {
		if err := accountAvailableForModel(account, model); err != nil {
			lastErr = err
			continue
		}
		release, ok, retryAfter := tryAcquireAccountSlot(account)
		if !ok {
			lastErr = fmt.Errorf("account %s rate limited, retry after %s", account.Name, retryAfter.Round(time.Millisecond))
			continue
		}
		return account, release, nil
	}
	if lastErr != nil {
		return TokenAccount{}, nil, fmt.Errorf("нет доступных аккаунтов группы %s для модели %s: %v", groupName, model, lastErr)
	}
	return TokenAccount{}, nil, fmt.Errorf("нет доступных аккаунтов группы %s для модели %s", groupName, model)
}

func accountAvailableForModel(account TokenAccount, model string) error {
	if account.Token.Disabled {
		return fmt.Errorf("account %s is disabled", account.Name)
	}
	if err := tokenExpiryError(account.Token, time.Now()); err != nil {
		return err
	}
	if account.Token.CreditsRemaining != nil && *account.Token.CreditsRemaining <= 0 {
		return fmt.Errorf("account %s has no credits", account.Name)
	}
	model = mappedModelID(model)
	if model == "" || model == "auto" {
		return nil
	}
	models, err := fetchAvailableModels(account)
	if err != nil {
		return err
	}
	for _, available := range models {
		if available.ModelID == model {
			return nil
		}
	}
	return fmt.Errorf("account %s does not support model %s", account.Name, model)
}

func mappedModelID(model string) string {
	if mapped, ok := ModelMap[model]; ok {
		return mapped
	}
	return model
}

func accountStatus(account TokenAccount) (string, string) {
	switch {
	case account.Token.LastCheckError != "":
		return "error", account.Token.LastCheckError
	case account.Token.Disabled:
		return "error", "Аккаунт выключен"
	case account.Token.CreditsRemaining != nil && *account.Token.CreditsRemaining <= 0:
		return "error", "Credits закончились"
	case account.Token.CreditsRemaining == nil:
		return "error", "Credits не проверены"
	case tokenExpiryError(account.Token, time.Now()) != nil:
		return "error", "KAS token истек"
	case account.Token.LastTestDurationMs == nil:
		return "error", "Аккаунт не проверен"
	default:
		return "ok", "Аккаунт доступен"
	}
}

func tokenAccountInfo(account TokenAccount, activeName string) AccountInfo {
	status, statusMessage := accountStatus(account)
	return AccountInfo{
		Name:               account.Name,
		Path:               account.Path,
		ExpiresAt:          account.Token.ExpiresAt,
		Active:             false,
		HasAccessToken:     account.Token.AccessToken != "",
		HasProfileArn:      account.Token.ProfileArn != "",
		AccessTokenPreview: maskToken(account.Token.AccessToken),
		ProfileArn:         account.Token.ProfileArn,
		APIKey:             account.Token.APIKey,
		APIKeyPreview:      maskToken(account.Token.APIKey),
		Group:              account.Token.Group,
		Enabled:            !account.Token.Disabled,
		Status:             status,
		StatusMessage:      statusMessage,
		RPS:                account.Token.RPS,
		Concurrency:        account.Token.Concurrency,
		CreditsRemaining:   account.Token.CreditsRemaining,
		LastTestDurationMs: account.Token.LastTestDurationMs,
		LastCheckError:     account.Token.LastCheckError,
	}
}

func writeTokenAccount(name string, token TokenData) (TokenAccount, error) {
	name = sanitizeAccountName(name)
	if name == "" {
		return TokenAccount{}, fmt.Errorf("name обязателен")
	}
	if token.AccessToken == "" {
		return TokenAccount{}, fmt.Errorf("accessToken обязателен")
	}
	if token.RefreshToken == "" {
		return TokenAccount{}, fmt.Errorf("refreshToken обязателен")
	}
	if token.APIKey == "" {
		token.APIKey = generateAPIKey()
	}
	normalizeTokenDefaults(&token)
	if err := os.MkdirAll(getTokenDir(), 0700); err != nil {
		return TokenAccount{}, fmt.Errorf("создать token директорию: %v", err)
	}

	path := filepath.Join(getTokenDir(), name+".json")
	data, err := jsonStr.MarshalIndent(token, "", "  ")
	if err != nil {
		return TokenAccount{}, fmt.Errorf("сериализовать token: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return TokenAccount{}, fmt.Errorf("записать token файл: %v", err)
	}

	return TokenAccount{Name: name, Path: path, Token: token}, nil
}

func persistTokenAccount(account TokenAccount) error {
	data, err := jsonStr.MarshalIndent(account.Token, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(account.Path, data, 0600)
}

// readToken 读取并显示token信息
func readToken() {
	account, err := selectTokenAccount("")
	if err != nil {
		fmt.Printf("读取token失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Token信息:")
	fmt.Printf("Account: %s\n", account.Name)
	fmt.Printf("Path: %s\n", account.Path)
	fmt.Printf("Access Token: %s\n", maskToken(account.Token.AccessToken))
	fmt.Printf("API Key: %s\n", account.Token.APIKey)
	fmt.Printf("Profile ARN: %s\n", account.Token.ProfileArn)
	if account.Token.ExpiresAt != "" {
		fmt.Printf("过期时间: %s\n", account.Token.ExpiresAt)
	}
}

// exportEnvVars 导出环境变量
func exportEnvVars() {
	account, err := selectTokenAccount("")
	if err != nil {
		fmt.Printf("读取 token失败,请先安装 Kiro 并登录！: %v\n", err)
		os.Exit(1)
	}

	// 根据操作系统输出不同格式的环境变量设置命令
	if runtime.GOOS == "windows" {
		fmt.Println("CMD")
		fmt.Printf("set ANTHROPIC_BASE_URL=http://localhost:8080\n")
		fmt.Printf("set ANTHROPIC_API_KEY=%s\n\n", account.Token.APIKey)
		fmt.Println("Powershell")
		fmt.Println(`$env:ANTHROPIC_BASE_URL="http://localhost:8080"`)
		fmt.Printf(`$env:ANTHROPIC_API_KEY="%s"`, account.Token.APIKey)
	} else {
		fmt.Printf("export ANTHROPIC_BASE_URL=http://localhost:8080\n")
		fmt.Printf("export ANTHROPIC_API_KEY=\"%s\"\n", account.Token.APIKey)
	}
}

func setClaude() {
	// C:\Users\WIN10\.claude.json
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("获取用户目录失败: %v\n", err)
		os.Exit(1)
	}

	claudeJsonPath := filepath.Join(homeDir, ".claude.json")
	ok, _ := FileExists(claudeJsonPath)
	if !ok {
		fmt.Println("未找到Claude配置文件，请确认是否已安装 Claude Code")
		fmt.Println("npm install -g @anthropic-ai/claude-code")
		os.Exit(1)
	}

	data, err := os.ReadFile(claudeJsonPath)
	if err != nil {
		fmt.Printf("读取 Claude 文件失败: %v\n", err)
		os.Exit(1)
	}

	var jsonData map[string]interface{}

	err = jsonStr.Unmarshal(data, &jsonData)

	if err != nil {
		fmt.Printf("解析 JSON 文件失败: %v\n", err)
		os.Exit(1)
	}

	jsonData["hasCompletedOnboarding"] = true
	jsonData["kiro-admin"] = true

	newJson, err := json.MarshalIndent(jsonData, "", "  ")

	if err != nil {
		fmt.Printf("生成 JSON 文件失败: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(claudeJsonPath, newJson, 0644)

	if err != nil {
		fmt.Printf("写入 JSON 文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Claude 配置文件已更新")

}

// getToken 获取当前token
func getToken() (TokenData, error) {
	account, err := selectTokenAccount("")
	if err != nil {
		return TokenData{}, err
	}

	return account.Token, nil
}

// logMiddleware 记录所有HTTP请求的中间件
func logMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// fmt.Printf("\n=== 收到请求 ===\n")
		// fmt.Printf("时间: %s\n", startTime.Format("2006-01-02 15:04:05"))
		// fmt.Printf("请求方法: %s\n", r.Method)
		// fmt.Printf("请求路径: %s\n", r.URL.Path)
		// fmt.Printf("客户端IP: %s\n", r.RemoteAddr)
		// fmt.Printf("请求头:\n")
		// for name, values := range r.Header {
		// 	fmt.Printf("  %s: %s\n", name, strings.Join(values, ", "))
		// }

		// 调用下一个处理器
		next(w, r)

		// 计算处理时间
		duration := time.Since(startTime)
		fmt.Printf("处理时间: %v\n", duration)
		fmt.Printf("=== 请求结束 ===\n\n")
	}
}

func adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminPasswordConfigured() {
			writeAdminAuthRequired(w, r, http.StatusServiceUnavailable, "admin password is not configured")
			return
		}
		if !validAdminSession(r) {
			writeAdminAuthRequired(w, r, http.StatusUnauthorized, "admin authentication required")
			return
		}
		next(w, r)
	}
}

func writeAdminAuthRequired(w http.ResponseWriter, r *http.Request, status int, message string) {
	if strings.HasPrefix(r.URL.Path, "/admin/api/") {
		writeJSONError(w, status, message)
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func adminPasswordConfigured() bool {
	settings := loadAdminSettings()
	return strings.TrimSpace(os.Getenv("KIRO_ADMIN_PASSWORD")) != "" || strings.TrimSpace(settings.AdminPasswordHash) != ""
}

func verifyAdminPassword(password string) bool {
	if password == "" {
		return false
	}
	settings := loadAdminSettings()
	if settings.AdminPasswordHash != "" {
		return verifyPasswordHash(settings.AdminPasswordHash, password)
	}
	envPassword := os.Getenv("KIRO_ADMIN_PASSWORD")
	return subtle.ConstantTimeCompare([]byte(password), []byte(envPassword)) == 1
}

func currentAdminPasswordFingerprint() string {
	settings := loadAdminSettings()
	if settings.AdminPasswordHash != "" {
		return settings.AdminPasswordHash
	}
	return os.Getenv("KIRO_ADMIN_PASSWORD")
}

func makeAdminSession(passwordFingerprint string, now time.Time) string {
	expiresAt := now.Add(adminSessionTTL).Unix()
	nonceBytes := make([]byte, 16)
	if _, err := cryptoRand.Read(nonceBytes); err != nil {
		nonceBytes = []byte(generateUUID())
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	payload := fmt.Sprintf("%d.%s", expiresAt, nonce)
	mac := hmac.New(sha256.New, []byte(passwordFingerprint))
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validAdminSession(r *http.Request) bool {
	cookie, err := r.Cookie(adminSessionCookie)
	if err != nil {
		return false
	}
	fingerprint := currentAdminPasswordFingerprint()
	if fingerprint == "" {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 {
		return false
	}
	expiresAt, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || nowFunc().Unix() > expiresAt {
		return false
	}
	payload := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(fingerprint))
	mac.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[2]), []byte(want))
}

func setAdminSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    makeAdminSession(currentAdminPasswordFingerprint(), nowFunc()),
		Path:     "/admin",
		Expires:  nowFunc().Add(adminSessionTTL),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearAdminSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    "",
		Path:     "/admin",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func hashAdminPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := cryptoRand.Read(salt); err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(salt, []byte(password)...))
	return "v1$" + base64.RawURLEncoding.EncodeToString(salt) + "$" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func verifyPasswordHash(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 3 || parts[0] != "v1" {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256(append(salt, []byte(password)...))
	return subtle.ConstantTimeCompare(sum[:], want) == 1
}

func adminSettingsResponse(settings AdminSettings) AdminSettingsResponse {
	settings = normalizeAdminSettings(settings)
	return AdminSettingsResponse{
		Groups:          accountGroupInfos(settings),
		StatsResetAt:    settings.StatsResetAt,
		HasPassword:     adminPasswordConfigured(),
		UsesEnvPassword: settings.AdminPasswordHash == "" && strings.TrimSpace(os.Getenv("KIRO_ADMIN_PASSWORD")) != "",
	}
}

func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if adminPasswordConfigured() && validAdminSession(r) {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(adminLoginHTML))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !adminPasswordConfigured() {
			http.Error(w, "admin password is not configured", http.StatusServiceUnavailable)
			return
		}
		if !verifyAdminPassword(r.FormValue("password")) {
			http.Error(w, "invalid password", http.StatusUnauthorized)
			return
		}
		setAdminSessionCookie(w)
		http.Redirect(w, r, "/admin", http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clearAdminSessionCookie(w)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func handleAdminPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req AdminPasswordRequest
	if err := jsonStr.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.NewPassword = strings.TrimSpace(req.NewPassword)
	if len(req.NewPassword) < 8 {
		writeJSONError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	if !verifyAdminPassword(req.CurrentPassword) {
		writeJSONError(w, http.StatusUnauthorized, "current password is invalid")
		return
	}
	hash, err := hashAdminPassword(req.NewPassword)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	settings := loadAdminSettings()
	settings.AdminPasswordHash = hash
	if err := saveAdminSettings(settings); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	setAdminSessionCookie(w)
	writeJSON(w, http.StatusOK, adminSettingsResponse(settings))
}

func handleAdminPasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req AdminPasswordRequest
	if err := jsonStr.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !verifyAdminPassword(req.CurrentPassword) {
		writeJSONError(w, http.StatusUnauthorized, "current password is invalid")
		return
	}
	if strings.TrimSpace(os.Getenv("KIRO_ADMIN_PASSWORD")) == "" {
		writeJSONError(w, http.StatusBadRequest, "KIRO_ADMIN_PASSWORD is not configured")
		return
	}
	settings := loadAdminSettings()
	settings.AdminPasswordHash = ""
	if err := saveAdminSettings(settings); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	setAdminSessionCookie(w)
	writeJSON(w, http.StatusOK, adminSettingsResponse(settings))
}

// startServer 启动HTTP代理服务器
func startServer(port string) {
	loadRequestHistory()

	// 创建路由器
	mux := http.NewServeMux()

	// 注册所有端点
	mux.HandleFunc("/v1/messages", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// 只处理POST请求
		if r.Method != http.MethodPost {
			fmt.Printf("错误: 不支持的请求方法\n")
			http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
			return
		}

		// 读取请求体
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Printf("错误: 读取请求体失败: %v\n", err)
			http.Error(w, fmt.Sprintf("读取请求体失败: %v", err), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		fmt.Printf("\n=========================Anthropic 请求体:\n%s\n=======================================\n", string(body))

		// 解析 Anthropic 请求
		var anthropicReq AnthropicRequest
		if err := jsonStr.Unmarshal(body, &anthropicReq); err != nil {
			fmt.Printf("错误: 解析请求体失败: %v\n", err)
			http.Error(w, fmt.Sprintf("解析请求体失败: %v", err), http.StatusBadRequest)
			return
		}

		if err := validateAnthropicRequest(anthropicReq); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		// 获取当前token。Для общего ключа аккаунт выбирается после чтения модели.
		account, release, err := selectTokenAccountForRequest(r, anthropicReq.Model)
		if err != nil {
			fmt.Printf("错误: 获取token失败: %v\n", err)
			http.Error(w, fmt.Sprintf("获取token失败: %v", err), http.StatusTooManyRequests)
			return
		}
		if release != nil {
			defer release()
		}

		// 如果是流式请求
		start := time.Now()
		logEntry := RequestLogEntry{
			ID:      generateUUID(),
			Account: account.Name,
			APIKey:  maskToken(account.Token.APIKey),
			Model:   anthropicReq.Model,
			Stream:  anthropicReq.Stream,
		}
		if anthropicReq.Stream {
			status, inputTokens, outputTokens, errText := handleStreamRequest(w, anthropicReq, account)
			logEntry.Status = status
			logEntry.InputTokens = inputTokens
			logEntry.OutputTokens = outputTokens
			logEntry.Error = errText
			logEntry.DurationMs = time.Since(start).Milliseconds()
			addRequestHistory(logEntry)
			maybeRefreshCreditsAfterRequest(account, logEntry.ID)
			return
		}

		// 非流式请求处理
		status, inputTokens, outputTokens, errText := handleNonStreamRequest(w, anthropicReq, account)
		logEntry.Status = status
		logEntry.InputTokens = inputTokens
		logEntry.OutputTokens = outputTokens
		logEntry.Error = errText
		logEntry.DurationMs = time.Since(start).Milliseconds()
		addRequestHistory(logEntry)
		maybeRefreshCreditsAfterRequest(account, logEntry.ID)
	}))
	mux.HandleFunc("/v1/chat/completions", logMiddleware(handleOpenAIChatCompletions))
	mux.HandleFunc("/chat/completions", logMiddleware(handleOpenAIChatCompletions))

	mux.HandleFunc("/admin/login", logMiddleware(handleAdminLogin))
	mux.HandleFunc("/admin/logout", logMiddleware(handleAdminLogout))
	mux.HandleFunc("/admin", logMiddleware(adminAuthMiddleware(handleAdminUI)))
	mux.HandleFunc("/admin/", logMiddleware(adminAuthMiddleware(handleAdminUI)))
	mux.HandleFunc("/admin/api/config", logMiddleware(adminAuthMiddleware(handleAdminConfig)))
	mux.HandleFunc("/admin/api/settings", logMiddleware(adminAuthMiddleware(handleAdminSettings)))
	mux.HandleFunc("/admin/api/groups", logMiddleware(adminAuthMiddleware(handleAdminGroups)))
	mux.HandleFunc("/admin/api/groups/", logMiddleware(adminAuthMiddleware(handleAdminGroupAction)))
	mux.HandleFunc("/admin/api/password", logMiddleware(adminAuthMiddleware(handleAdminPassword)))
	mux.HandleFunc("/admin/api/password/reset", logMiddleware(adminAuthMiddleware(handleAdminPasswordReset)))
	mux.HandleFunc("/admin/api/auth/start", logMiddleware(adminAuthMiddleware(handleAdminAuthStart)))
	mux.HandleFunc("/admin/api/auth/", logMiddleware(adminAuthMiddleware(handleAdminAuthStatus)))
	mux.HandleFunc("/admin/api/accounts", logMiddleware(adminAuthMiddleware(handleAdminAccounts)))
	mux.HandleFunc("/admin/api/accounts/", logMiddleware(adminAuthMiddleware(handleAdminAccountAction)))
	mux.HandleFunc("/admin/api/balance", logMiddleware(adminAuthMiddleware(handleAdminBalance)))
	mux.HandleFunc("/admin/api/history", logMiddleware(adminAuthMiddleware(handleAdminHistory)))
	mux.HandleFunc("/admin/api/stats/reset", logMiddleware(adminAuthMiddleware(handleAdminStatsReset)))
	mux.HandleFunc("/admin/api/usage", logMiddleware(adminAuthMiddleware(handleAdminUsage)))
	mux.HandleFunc("/api/usage/token/", logMiddleware(handleNewAPITokenUsage))
	mux.HandleFunc("/dashboard/billing/credit_grants", logMiddleware(handleOpenAICreditGrants))
	mux.HandleFunc("/v1/dashboard/billing/credit_grants", logMiddleware(handleOpenAICreditGrants))
	mux.HandleFunc("/v1/dashboard/billing/subscription", logMiddleware(handleOpenAISubscription))
	mux.HandleFunc("/v1/dashboard/billing/usage", logMiddleware(handleOpenAIUsage))
	mux.HandleFunc("/models", logMiddleware(handleModels))
	mux.HandleFunc("/v1/models", logMiddleware(handleModels))

	// 添加健康检查端点
	mux.HandleFunc("/health", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// 添加404处理
	mux.HandleFunc("/", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("警告: 访问未知端点\n")
		http.Error(w, "404 未找到", http.StatusNotFound)
	}))

	// 启动服务器
	fmt.Printf("启动Anthropic API代理服务器，监听端口: %s\n", port)
	fmt.Printf("可用端点:\n")
	fmt.Printf("  POST /v1/messages - Anthropic API代理\n")
	fmt.Printf("  POST /v1/chat/completions - OpenAI Chat Completions兼容代理\n")
	fmt.Printf("  GET  /health      - 健康检查\n")
	fmt.Printf("按Ctrl+C停止服务器\n")

	startKASTokenRefreshScheduler()
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Printf("启动服务器失败: %v\n", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := jsonStr.NewEncoder(w).Encode(data); err != nil {
		fmt.Printf("ошибка записи JSON: %v\n", err)
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func handleOpenAIChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "only POST is supported")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, fmt.Sprintf("read request body: %v", err))
		return
	}
	defer r.Body.Close()

	var openAIReq OpenAIChatCompletionRequest
	if err := jsonStr.Unmarshal(body, &openAIReq); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, fmt.Sprintf("parse request body: %v", err))
		return
	}

	anthropicReq, err := openAIRequestToAnthropic(openAIReq)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateAnthropicRequest(anthropicReq); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error())
		return
	}

	account, release, err := selectTokenAccountForRequest(r, anthropicReq.Model)
	if err != nil {
		writeOpenAIError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	if release != nil {
		defer release()
	}

	start := time.Now()
	logEntry := RequestLogEntry{
		ID:      generateUUID(),
		Account: account.Name,
		APIKey:  maskToken(account.Token.APIKey),
		Model:   anthropicReq.Model,
		Stream:  openAIReq.Stream,
	}

	recorder := localResponseRecorder{header: http.Header{}}
	status, inputTokens, outputTokens, errText := handleNonStreamRequest(&recorder, anthropicReq, account)
	logEntry.Status = status
	logEntry.InputTokens = inputTokens
	logEntry.OutputTokens = outputTokens
	logEntry.Error = errText
	logEntry.DurationMs = time.Since(start).Milliseconds()
	addRequestHistory(logEntry)
	maybeRefreshCreditsAfterRequest(account, logEntry.ID)

	if status != http.StatusOK {
		writeOpenAIError(w, http.StatusBadGateway, strings.TrimSpace(recorder.body.String()))
		return
	}

	var anthropicResp anthropicMessageResponse
	if err := jsonStr.Unmarshal(recorder.body.Bytes(), &anthropicResp); err != nil {
		writeOpenAIError(w, http.StatusBadGateway, fmt.Sprintf("parse anthropic response: %v", err))
		return
	}

	text, toolCalls := openAIContentFromAnthropic(anthropicResp)
	if openAIReq.Stream {
		writeOpenAIStreamResponse(w, openAIReq.Model, text, toolCalls, anthropicResp.Usage.InputTokens, anthropicResp.Usage.OutputTokens)
		return
	}
	writeOpenAIChatResponse(w, openAIReq.Model, text, toolCalls, anthropicResp.Usage.InputTokens, anthropicResp.Usage.OutputTokens)
}

type localResponseRecorder struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func (r *localResponseRecorder) Header() http.Header {
	return r.header
}

func (r *localResponseRecorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
}

func (r *localResponseRecorder) Write(data []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(data)
}

func openAIContentFromAnthropic(resp anthropicMessageResponse) (string, []map[string]any) {
	var texts []string
	var toolCalls []map[string]any
	for _, item := range resp.Content {
		switch item.Type {
		case "text":
			texts = append(texts, item.Text)
		case "tool_use":
			args, _ := jsonStr.Marshal(item.Input)
			toolCalls = append(toolCalls, map[string]any{
				"id":   item.ID,
				"type": "function",
				"function": map[string]any{
					"name":      item.Name,
					"arguments": string(args),
				},
			})
		}
	}
	return strings.Join(texts, ""), toolCalls
}

func writeOpenAIChatResponse(w http.ResponseWriter, model, text string, toolCalls []map[string]any, inputTokens, outputTokens int) {
	message := map[string]any{
		"role":    "assistant",
		"content": text,
	}
	finishReason := "stop"
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
		finishReason = "tool_calls"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      "chatcmpl-" + strings.ReplaceAll(generateUUID(), "-", ""),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
		"usage": map[string]any{
			"prompt_tokens":     inputTokens,
			"completion_tokens": outputTokens,
			"total_tokens":      inputTokens + outputTokens,
		},
	})
}

func writeOpenAIStreamResponse(w http.ResponseWriter, model, text string, toolCalls []map[string]any, inputTokens, outputTokens int) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)
	id := "chatcmpl-" + strings.ReplaceAll(generateUUID(), "-", "")
	created := time.Now().Unix()

	writeOpenAIStreamChunk(w, flusher, map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{"role": "assistant"},
		}},
	})

	if len(toolCalls) > 0 {
		writeOpenAIStreamChunk(w, flusher, map[string]any{
			"id":      id,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{{
				"index": 0,
				"delta": map[string]any{"tool_calls": toolCalls},
			}},
		})
	} else if text != "" {
		writeOpenAIStreamChunk(w, flusher, map[string]any{
			"id":      id,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{{
				"index": 0,
				"delta": map[string]any{"content": text},
			}},
		})
	}

	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}
	writeOpenAIStreamChunk(w, flusher, map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": finishReason,
		}},
		"usage": map[string]any{
			"prompt_tokens":     inputTokens,
			"completion_tokens": outputTokens,
			"total_tokens":      inputTokens + outputTokens,
		},
	})
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func writeOpenAIStreamChunk(w http.ResponseWriter, flusher http.Flusher, data any) {
	raw, err := jsonStr.Marshal(data)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", raw)
	if flusher != nil {
		flusher.Flush()
	}
}

func writeOpenAIError(w http.ResponseWriter, status int, message string) {
	if strings.TrimSpace(message) == "" {
		message = http.StatusText(status)
	}
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "kiro-admin_error",
		},
	})
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if group, ok, err := requestAccountGroup(r); err == nil && ok {
		models, err := fetchAvailableModelsForGroup(group.Name)
		if err == nil && len(models) > 0 {
			writeModelsResponse(w, models)
			return
		}
	}

	if account, err := selectTokenAccountFromRequest(r); err == nil {
		models, err := fetchAvailableModels(account)
		if err == nil && len(models) > 0 {
			writeModelsResponse(w, models)
			return
		}
	}

	writeModelsResponse(w, fallbackModels())
}

func requestAccountGroup(r *http.Request) (AccountGroup, bool, error) {
	key := requestAPIKey(r)
	if key == "" {
		return AccountGroup{}, false, nil
	}
	return selectAccountGroupByAPIKey(key)
}

func fetchAvailableModelsForGroup(groupName string) ([]CodeWhispererModel, error) {
	accounts, err := listTokenAccounts()
	if err != nil {
		return nil, err
	}
	groupName = sanitizeGroupName(groupName)
	byID := map[string]CodeWhispererModel{}
	var lastErr error
	for _, account := range accounts {
		if sanitizeGroupName(account.Token.Group) != groupName {
			continue
		}
		models, err := fetchAvailableModels(account)
		if err != nil {
			lastErr = err
			continue
		}
		for _, model := range models {
			if _, ok := byID[model.ModelID]; !ok {
				byID[model.ModelID] = model
			}
		}
	}
	if len(byID) == 0 && lastErr != nil {
		return nil, lastErr
	}
	models := make([]CodeWhispererModel, 0, len(byID))
	for _, model := range byID {
		models = append(models, model)
	}
	return models, nil
}

func writeModelsResponse(w http.ResponseWriter, models []CodeWhispererModel) {
	sort.Slice(models, func(i, j int) bool {
		return models[i].ModelID < models[j].ModelID
	})

	data := make([]map[string]any, 0, len(models))
	for _, model := range models {
		item := map[string]any{
			"id":       model.ModelID,
			"object":   "model",
			"created":  0,
			"owned_by": "kiro-admin",
		}
		if model.ModelName != "" {
			item["name"] = model.ModelName
		}
		if model.Description != "" {
			item["description"] = model.Description
		}
		if model.RateMultiplier > 0 {
			item["rate_multiplier"] = model.RateMultiplier
		}
		if model.RateUnit != "" {
			item["rate_unit"] = model.RateUnit
		}
		data = append(data, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

func fallbackModels() []CodeWhispererModel {
	seen := make(map[string]struct{}, len(ModelMap))
	models := make([]CodeWhispererModel, 0, len(ModelMap))
	for _, id := range ModelMap {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		models = append(models, CodeWhispererModel{ModelID: id})
	}
	return models
}

func addRequestHistory(entry RequestLogEntry) {
	requestHistory.Lock()
	defer requestHistory.Unlock()

	if entry.ID == "" {
		entry.ID = generateUUID()
	}
	if entry.Time == "" {
		entry.Time = time.Now().Format(time.RFC3339)
	}
	requestHistory.entries = append([]RequestLogEntry{entry}, requestHistory.entries...)
	if len(requestHistory.entries) > maxRequestHistory {
		requestHistory.entries = requestHistory.entries[:maxRequestHistory]
	}
	saveRequestHistoryLocked()
}

func updateRequestHistoryCreditsSpent(id string, spent float64) {
	if spent < 0 {
		return
	}

	requestHistory.Lock()
	defer requestHistory.Unlock()

	for i := range requestHistory.entries {
		if requestHistory.entries[i].ID != id {
			continue
		}
		requestHistory.entries[i].CreditsSpent = &spent
		saveRequestHistoryLocked()
		return
	}
}

func getRequestHistory() []RequestLogEntry {
	requestHistory.Lock()
	defer requestHistory.Unlock()

	entries := make([]RequestLogEntry, len(requestHistory.entries))
	copy(entries, requestHistory.entries)
	return entries
}

func clearRequestHistory() {
	requestHistory.Lock()
	defer requestHistory.Unlock()

	requestHistory.entries = nil
	saveRequestHistoryLocked()
}

func filterRequestHistory(entries []RequestLogEntry, rangeName, sinceText, fromText, toText string) []RequestLogEntry {
	since, until := historyRangeBounds(rangeName, nowFunc())
	if parsedFrom, ok := parseHistoryTime(fromText); ok {
		since = parsedFrom
	}
	if parsedTo, ok := parseHistoryTime(toText); ok {
		until = parsedTo
	}
	if parsedSince, ok := parseHistoryTime(sinceText); ok && (since.IsZero() || parsedSince.After(since)) {
		since = parsedSince
	}
	filtered := make([]RequestLogEntry, 0, len(entries))
	for _, entry := range entries {
		t, ok := parseHistoryTime(entry.Time)
		if !ok {
			continue
		}
		if !since.IsZero() && t.Before(since) {
			continue
		}
		if !until.IsZero() && !t.Before(until) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func historyRangeBounds(rangeName string, now time.Time) (time.Time, time.Time) {
	year, month, day := now.Date()
	today := time.Date(year, month, day, 0, 0, 0, 0, now.Location())
	switch rangeName {
	case "last_5m":
		return now.Add(-5 * time.Minute), time.Time{}
	case "last_15m":
		return now.Add(-15 * time.Minute), time.Time{}
	case "last_1h":
		return now.Add(-time.Hour), time.Time{}
	case "last_6h":
		return now.Add(-6 * time.Hour), time.Time{}
	case "last_24h":
		return now.Add(-24 * time.Hour), time.Time{}
	case "today":
		return today, today.AddDate(0, 0, 1)
	case "yesterday":
		return today.AddDate(0, 0, -1), today
	case "seven_days", "last_7d":
		return today.AddDate(0, 0, -6), time.Time{}
	default:
		return time.Time{}, time.Time{}
	}
}

func parseHistoryTime(text string) (time.Time, bool) {
	if strings.TrimSpace(text) == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, text)
	if err == nil {
		return t, true
	}
	t, err = time.Parse(time.RFC3339Nano, text)
	if err == nil {
		return t, true
	}
	return time.Time{}, false
}

func requestStats(entries []RequestLogEntry) RequestStats {
	stats := RequestStats{
		StatusCounts: map[string]int{},
		ErrorCounts:  map[string]int{},
	}
	byAccount := map[string]*AccountRequestStats{}
	durationTotals := map[string]int64{}
	for _, entry := range entries {
		stats.Total++
		statusKey := strconv.Itoa(entry.Status)
		stats.StatusCounts[statusKey]++
		accountName := entry.Account
		if accountName == "" {
			accountName = "-"
		}
		accountStats := byAccount[accountName]
		if accountStats == nil {
			accountStats = &AccountRequestStats{Name: accountName}
			byAccount[accountName] = accountStats
		}
		accountStats.Total++
		durationTotals[accountName] += entry.DurationMs
		if entry.Status >= 200 && entry.Status < 400 && entry.Error == "" {
			stats.Success++
			accountStats.Success++
			continue
		}
		stats.Failed++
		accountStats.Failed++
		if entry.Error != "" {
			errorKey := summarizeError(entry.Error)
			stats.ErrorCounts[errorKey]++
			if accountStats.LastError == "" {
				accountStats.LastError = errorKey
			}
		}
	}
	for name, accountStats := range byAccount {
		if accountStats.Total > 0 {
			accountStats.FailureRate = float64(accountStats.Failed) / float64(accountStats.Total)
			accountStats.AvgDuration = durationTotals[name] / int64(accountStats.Total)
		}
		stats.Accounts = append(stats.Accounts, *accountStats)
	}
	sort.Slice(stats.Accounts, func(i, j int) bool {
		if stats.Accounts[i].FailureRate != stats.Accounts[j].FailureRate {
			return stats.Accounts[i].FailureRate > stats.Accounts[j].FailureRate
		}
		if stats.Accounts[i].Failed != stats.Accounts[j].Failed {
			return stats.Accounts[i].Failed > stats.Accounts[j].Failed
		}
		return stats.Accounts[i].Name < stats.Accounts[j].Name
	})
	return stats
}

func summarizeError(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	switch {
	case strings.Contains(text, "Too many requests"):
		return "429 Too many requests"
	case strings.Contains(text, "INSUFFICIENT_MODEL_CAPACITY"):
		return "429 insufficient model capacity"
	case strings.Contains(text, "CodeWhisperer status:"):
		parts := strings.SplitN(text, ",", 2)
		return strings.TrimSpace(parts[0])
	default:
		if len(text) > 120 {
			return text[:120]
		}
		return text
	}
}

func handleAdminHistory(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodDelete:
		clearRequestHistory()
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
		return
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	settings := loadAdminSettings()
	entries := getRequestHistory()
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "all"
	}
	fromText := r.URL.Query().Get("from")
	toText := r.URL.Query().Get("to")
	historyEntries := filterRequestHistory(entries, rangeName, "", fromText, toText)
	statsEntries := filterRequestHistory(entries, rangeName, settings.StatsResetAt, fromText, toText)
	writeJSON(w, http.StatusOK, map[string]any{
		"requests":     historyEntries,
		"stats":        requestStats(statsEntries),
		"range":        rangeName,
		"from":         fromText,
		"to":           toText,
		"statsResetAt": settings.StatsResetAt,
	})
}

func handleAdminStatsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	settings := loadAdminSettings()
	settings.StatsResetAt = nowFunc().Format(time.RFC3339)
	if err := saveAdminSettings(settings); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reset": true, "statsResetAt": settings.StatsResetAt})
}

func handleNewAPITokenUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	account, available, refreshErr, ok := accountCreditsForRequest(w, r)
	if !ok {
		return
	}

	data := map[string]any{
		"object":               "token_usage",
		"name":                 account.Name,
		"total_granted":        available,
		"total_used":           0,
		"total_available":      available,
		"unlimited_quota":      false,
		"model_limits":         map[string]any{},
		"model_limits_enabled": false,
		"expires_at":           tokenExpiresAtUnix(account.Token.ExpiresAt),
	}
	if refreshErr != nil {
		data["refresh_error"] = userFriendlyCreditsError(refreshErr)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code":    true,
		"message": "ok",
		"data":    data,
	})
}

func handleOpenAICreditGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	_, available, _, ok := accountCreditsForRequest(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":          "credit_summary",
		"total_granted":   available,
		"total_used":      0,
		"total_available": available,
	})
}

func handleOpenAISubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	account, available, _, ok := accountCreditsForRequest(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":                "billing_subscription",
		"has_payment_method":    true,
		"soft_limit_usd":        available,
		"hard_limit_usd":        available,
		"system_hard_limit_usd": available,
		"access_until":          tokenExpiresAtUnix(account.Token.ExpiresAt),
	})
}

func handleOpenAIUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if _, _, _, ok := accountCreditsForRequest(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":      "list",
		"total_usage": 0,
	})
}

func accountCreditsForRequest(w http.ResponseWriter, r *http.Request) (TokenAccount, float64, error, bool) {
	if group, ok, err := requestAccountGroup(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"success": false,
			"message": err.Error(),
		})
		return TokenAccount{}, 0, err, false
	} else if ok {
		account, available, err := groupCreditsForRequest(group.Name)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"success": false,
				"message": userFriendlyCreditsError(err),
			})
			return TokenAccount{}, 0, err, false
		}
		return account, available, nil, true
	}

	account, err := selectTokenAccountFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"success": false,
			"message": err.Error(),
		})
		return TokenAccount{}, 0, err, false
	}

	updated, err := updateAccountCredits(account)
	if err == nil {
		account = updated
	} else if account.Token.CreditsRemaining == nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"success": false,
			"message": userFriendlyCreditsError(err),
		})
		return TokenAccount{}, 0, err, false
	}

	available := 0.0
	if account.Token.CreditsRemaining != nil {
		available = *account.Token.CreditsRemaining
	}
	return account, available, err, true
}

func groupCreditsForRequest(groupName string) (TokenAccount, float64, error) {
	accounts, err := listTokenAccounts()
	if err != nil {
		return TokenAccount{}, 0, err
	}

	groupName = sanitizeGroupName(groupName)
	var first TokenAccount
	var total float64
	hasCredits := false
	var lastErr error
	groupAccounts := 0
	for _, account := range accounts {
		if sanitizeGroupName(account.Token.Group) != groupName {
			continue
		}
		groupAccounts++
		if account.Token.Disabled {
			continue
		}
		if first.Name == "" {
			first = account
			first.Name = groupName
		}
		updated, err := updateAccountCredits(account)
		if err == nil {
			account = updated
		} else {
			lastErr = err
		}
		if account.Token.CreditsRemaining != nil {
			total += *account.Token.CreditsRemaining
			hasCredits = true
		}
	}
	if first.Name == "" {
		if groupAccounts > 0 {
			return TokenAccount{}, 0, fmt.Errorf("включенные token аккаунты группы %s не найдены", groupName)
		}
		return TokenAccount{}, 0, fmt.Errorf("token аккаунты группы %s не найдены", groupName)
	}
	if !hasCredits && lastErr != nil {
		return TokenAccount{}, 0, lastErr
	}
	return first, total, lastErr
}

func tokenExpiresAtUnix(expiresAt string) int64 {
	if strings.TrimSpace(expiresAt) == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func getHistoryFilePath() string {
	return filepath.Join(getTokenDir(), historyFileName)
}

func loadRequestHistory() {
	data, err := os.ReadFile(getHistoryFilePath())
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("request history load failed: %v\n", err)
		}
		return
	}

	var entries []RequestLogEntry
	if err := jsonStr.Unmarshal(data, &entries); err != nil {
		fmt.Printf("request history parse failed: %v\n", err)
		return
	}
	if len(entries) > maxRequestHistory {
		entries = entries[:maxRequestHistory]
	}

	requestHistory.Lock()
	requestHistory.entries = entries
	requestHistory.Unlock()
}

func saveRequestHistoryLocked() {
	if err := os.MkdirAll(getTokenDir(), 0700); err != nil {
		fmt.Printf("request history mkdir failed: %v\n", err)
		return
	}
	data, err := jsonStr.MarshalIndent(requestHistory.entries, "", "  ")
	if err != nil {
		fmt.Printf("request history marshal failed: %v\n", err)
		return
	}
	if err := os.WriteFile(getHistoryFilePath(), data, 0600); err != nil {
		fmt.Printf("request history write failed: %v\n", err)
	}
}

func getSettingsFilePath() string {
	return filepath.Join(getTokenDir(), settingsFileName)
}

func defaultAdminSettings() AdminSettings {
	return AdminSettings{}
}

func normalizeAdminSettings(settings AdminSettings) AdminSettings {
	seen := map[string]bool{}
	groups := make([]AccountGroup, 0, len(settings.Groups)+1)
	for _, group := range settings.Groups {
		group.Name = sanitizeGroupName(group.Name)
		if seen[group.Name] {
			continue
		}
		if group.APIKey == "" {
			group.APIKey = generateAPIKey()
		}
		seen[group.Name] = true
		groups = append(groups, group)
	}
	if len(groups) == 0 {
		groups = append(groups, AccountGroup{Name: defaultAccountGroup, APIKey: generateAPIKey()})
		seen[defaultAccountGroup] = true
	}
	settings.Groups = groups
	return settings
}

func accountGroupInfos(settings AdminSettings) []AccountGroupInfo {
	settings = normalizeAdminSettings(settings)
	accounts, _ := listTokenAccounts()
	byName := make(map[string]*AccountGroupInfo, len(settings.Groups))
	for _, group := range settings.Groups {
		byName[group.Name] = &AccountGroupInfo{
			Name:          group.Name,
			APIKey:        group.APIKey,
			APIKeyPreview: maskToken(group.APIKey),
		}
	}
	for _, account := range accounts {
		info := byName[sanitizeGroupName(account.Token.Group)]
		if info == nil {
			continue
		}
		info.Accounts++
		if !account.Token.Disabled {
			info.Enabled++
			if account.Token.CreditsRemaining != nil {
				if info.Credits == nil {
					zero := 0.0
					info.Credits = &zero
				}
				*info.Credits += *account.Token.CreditsRemaining
			}
		}
	}
	infos := make([]AccountGroupInfo, 0, len(settings.Groups))
	for _, group := range settings.Groups {
		infos = append(infos, *byName[group.Name])
	}
	return infos
}

func loadAdminSettings() AdminSettings {
	settings := defaultAdminSettings()
	data, err := os.ReadFile(getSettingsFilePath())
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("admin settings load failed: %v\n", err)
		}
		return settings
	}
	if err := jsonStr.Unmarshal(data, &settings); err != nil {
		fmt.Printf("admin settings parse failed: %v\n", err)
		return defaultAdminSettings()
	}
	return normalizeAdminSettings(settings)
}

func saveAdminSettings(settings AdminSettings) error {
	if err := os.MkdirAll(getTokenDir(), 0700); err != nil {
		return err
	}
	data, err := jsonStr.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getSettingsFilePath(), data, 0600)
}

func ensureAdminSettings() (AdminSettings, error) {
	settings := normalizeAdminSettings(loadAdminSettings())
	if err := saveAdminSettings(settings); err != nil {
		return settings, err
	}
	return settings, nil
}

func refreshCreditsForAccountName(name string) error {
	account, err := selectTokenAccount(name)
	if err != nil {
		return err
	}
	_, err = updateAccountCredits(account)
	return err
}

func refreshCreditsForAllAccounts() {
	accounts, err := listTokenAccounts()
	if err != nil {
		fmt.Printf("credits refresh accounts failed: %v\n", err)
		return
	}
	for _, account := range accounts {
		if _, err := updateAccountCredits(account); err != nil {
			fmt.Printf("credits refresh failed for %s: %v\n", account.Name, err)
		}
	}
}

func refreshExpiredKASTokens() {
	accounts, err := listTokenAccounts()
	if err != nil {
		fmt.Printf("KAS token refresh accounts failed: %v\n", err)
		return
	}
	now := time.Now()
	for _, account := range accounts {
		if !shouldRefreshKASToken(account.Token, now) {
			continue
		}
		if err := refreshKASToken(account); err != nil {
			fmt.Printf("KAS token refresh failed for %s: %v\n", account.Name, err)
		}
	}
}

func shouldRefreshKASToken(token TokenData, now time.Time) bool {
	if strings.TrimSpace(token.ExpiresAt) == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, token.ExpiresAt)
	if err != nil {
		return false
	}
	return !now.Before(expiresAt.Add(-tokenRefreshSkew))
}

func refreshKASToken(account TokenAccount) error {
	next, err := kasTokenRefresher(account)
	if err != nil {
		return err
	}
	if next.AccessToken == "" {
		return fmt.Errorf("refreshed KAS token missing accessToken")
	}
	if next.ProfileArn == "" {
		next.ProfileArn = account.Token.ProfileArn
	}

	next.APIKey = account.Token.APIKey
	next.Group = account.Token.Group
	next.Disabled = account.Token.Disabled
	next.RPS = account.Token.RPS
	next.Concurrency = account.Token.Concurrency
	next.Region = account.Token.Region
	next.StartURL = account.Token.StartURL
	next.OAuthFlow = account.Token.OAuthFlow
	next.Scopes = account.Token.Scopes
	next.ClientID = account.Token.ClientID
	next.ClientSecret = account.Token.ClientSecret
	next.ClientSecretExpiry = account.Token.ClientSecretExpiry
	if next.RefreshToken == "" {
		next.RefreshToken = account.Token.RefreshToken
	}
	next.CreditsRemaining = account.Token.CreditsRemaining
	next.LastTestDurationMs = account.Token.LastTestDurationMs
	next.LastCheckError = account.Token.LastCheckError
	account.Token = next
	return persistTokenAccount(account)
}

func refreshKASTokenFromCommand(account TokenAccount) (TokenData, error) {
	if account.Token.RefreshToken == "" {
		return TokenData{}, fmt.Errorf("account token missing refreshToken")
	}
	if isOIDCToken(account.Token) {
		return refreshKASTokenFromOIDC(account)
	}

	refreshed, err := refreshKiroSocialToken(account.Token.RefreshToken)
	if err != nil {
		return TokenData{}, err
	}
	if refreshed.AccessToken == "" {
		return TokenData{}, fmt.Errorf("kiro refresh response missing accessToken")
	}
	if refreshed.ProfileArn == "" {
		refreshed.ProfileArn = account.Token.ProfileArn
	}
	if account.Token.ProfileArn != "" && refreshed.ProfileArn != "" && account.Token.ProfileArn != refreshed.ProfileArn {
		return TokenData{}, fmt.Errorf("refreshed profile %s does not match account profile %s", refreshed.ProfileArn, account.Token.ProfileArn)
	}

	expiresAt := time.Now().Add(time.Duration(refreshed.ExpiresIn) * time.Second).UTC().Format(time.RFC3339Nano)
	if refreshed.ExpiresIn <= 0 {
		expiresAt = account.Token.ExpiresAt
	}
	refreshToken := refreshed.RefreshToken
	if refreshToken == "" {
		refreshToken = account.Token.RefreshToken
	}

	return TokenData{
		AccessToken:  refreshed.AccessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		ProfileArn:   refreshed.ProfileArn,
	}, nil
}

func isOIDCToken(token TokenData) bool {
	return strings.TrimSpace(token.ClientID) != "" ||
		strings.EqualFold(strings.TrimSpace(token.OAuthFlow), "PKCE") ||
		strings.TrimSpace(token.StartURL) != ""
}

func refreshKASTokenFromOIDC(account TokenAccount) (TokenData, error) {
	token := account.Token
	if strings.TrimSpace(token.ClientID) == "" || strings.TrimSpace(token.ClientSecret) == "" {
		return TokenData{}, fmt.Errorf("Builder ID token missing clientId/clientSecret from kirocli:odic:device-registration")
	}

	body := map[string]any{
		"clientId":     token.ClientID,
		"clientSecret": token.ClientSecret,
		"grantType":    "refresh_token",
		"refreshToken": token.RefreshToken,
	}
	if len(token.Scopes) > 0 {
		body["scope"] = token.Scopes
	}
	rawBody, err := jsonStr.Marshal(body)
	if err != nil {
		return TokenData{}, err
	}

	endpoint := oidcTokenEndpoint(token.Region)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(rawBody))
	if err != nil {
		return TokenData{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := newOutboundHTTPClient().Do(req)
	if err != nil {
		return TokenData{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return TokenData{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return TokenData{}, fmt.Errorf("kiro OIDC refresh status: %d, response: %s", resp.StatusCode, string(respBody))
	}

	var refreshed KiroOIDCRefreshResponse
	if err := jsonStr.Unmarshal(respBody, &refreshed); err != nil {
		return TokenData{}, err
	}
	if refreshed.AccessToken == "" {
		return TokenData{}, fmt.Errorf("kiro OIDC refresh response missing accessToken")
	}

	expiresAt := time.Now().Add(time.Duration(refreshed.ExpiresIn) * time.Second).UTC().Format(time.RFC3339Nano)
	if refreshed.ExpiresIn <= 0 {
		expiresAt = token.ExpiresAt
	}
	refreshToken := refreshed.RefreshToken
	if refreshToken == "" {
		refreshToken = token.RefreshToken
	}

	return TokenData{
		AccessToken:  refreshed.AccessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		ProfileArn:   token.ProfileArn,
	}, nil
}

func startKiroOIDCDeviceLogin() (*KiroOIDCLoginSession, error) {
	registration, err := registerKiroOIDCClient()
	if err != nil {
		return nil, err
	}
	authorization, err := startKiroOIDCDeviceAuthorization(registration)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(authorization.ExpiresIn) * time.Second)
	if authorization.ExpiresIn <= 0 {
		expiresAt = now.Add(kiroOIDCAuthSessionTTL)
	}
	session := &KiroOIDCLoginSession{
		ID:            strings.ReplaceAll(generateUUID(), "-", ""),
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
		Registration:  registration,
		Authorization: authorization,
	}

	oidcLoginSessions.Lock()
	if oidcLoginSessions.byID == nil {
		oidcLoginSessions.byID = make(map[string]*KiroOIDCLoginSession)
	}
	oidcLoginSessions.byID[session.ID] = session
	oidcLoginSessions.Unlock()

	return session, nil
}

func registerKiroOIDCClient() (KiroOIDCRegisterResponse, error) {
	body := map[string]any{
		"clientName": kiroOIDCClientName,
		"clientType": kiroOIDCClientType,
		"scopes":     kiroOIDCScopes,
	}
	rawBody, err := jsonStr.Marshal(body)
	if err != nil {
		return KiroOIDCRegisterResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, oidcRegisterEndpoint(kiroOIDCRegion), bytes.NewBuffer(rawBody))
	if err != nil {
		return KiroOIDCRegisterResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := newOutboundHTTPClient().Do(req)
	if err != nil {
		return KiroOIDCRegisterResponse{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return KiroOIDCRegisterResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return KiroOIDCRegisterResponse{}, fmt.Errorf("kiro OIDC register status: %d, response: %s", resp.StatusCode, string(respBody))
	}

	var registration KiroOIDCRegisterResponse
	if err := jsonStr.Unmarshal(respBody, &registration); err != nil {
		return KiroOIDCRegisterResponse{}, err
	}
	if registration.ClientID == "" || registration.ClientSecret == "" {
		return KiroOIDCRegisterResponse{}, fmt.Errorf("kiro OIDC register response missing clientId/clientSecret")
	}
	if registration.ClientSecretExpiresAt > 0 {
		registration.ClientSecretExpiresRFC = time.Unix(registration.ClientSecretExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	return registration, nil
}

func startKiroOIDCDeviceAuthorization(registration KiroOIDCRegisterResponse) (KiroOIDCDeviceAuthorizationResponse, error) {
	body := map[string]any{
		"clientId":     registration.ClientID,
		"clientSecret": registration.ClientSecret,
		"startUrl":     kiroOIDCStartURL,
	}
	rawBody, err := jsonStr.Marshal(body)
	if err != nil {
		return KiroOIDCDeviceAuthorizationResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, oidcDeviceAuthEndpoint(kiroOIDCRegion), bytes.NewBuffer(rawBody))
	if err != nil {
		return KiroOIDCDeviceAuthorizationResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := newOutboundHTTPClient().Do(req)
	if err != nil {
		return KiroOIDCDeviceAuthorizationResponse{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return KiroOIDCDeviceAuthorizationResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return KiroOIDCDeviceAuthorizationResponse{}, fmt.Errorf("kiro OIDC device authorization status: %d, response: %s", resp.StatusCode, string(respBody))
	}

	var authorization KiroOIDCDeviceAuthorizationResponse
	if err := jsonStr.Unmarshal(respBody, &authorization); err != nil {
		return KiroOIDCDeviceAuthorizationResponse{}, err
	}
	if authorization.DeviceCode == "" || authorization.UserCode == "" {
		return KiroOIDCDeviceAuthorizationResponse{}, fmt.Errorf("kiro OIDC device authorization response missing deviceCode/userCode")
	}
	if authorization.Interval <= 0 {
		authorization.Interval = 5
	}
	authorization.Region = kiroOIDCRegion
	authorization.StartURL = kiroOIDCStartURL
	return authorization, nil
}

func pollKiroOIDCLoginSession(id string) (*KiroOIDCLoginSession, string, error) {
	oidcLoginSessions.Lock()
	session := oidcLoginSessions.byID[id]
	if session == nil {
		oidcLoginSessions.Unlock()
		return nil, "", fmt.Errorf("auth session not found")
	}
	if session.CompletedToken != nil {
		oidcLoginSessions.Unlock()
		return session, "complete", nil
	}
	if time.Now().After(session.ExpiresAt) {
		delete(oidcLoginSessions.byID, id)
		oidcLoginSessions.Unlock()
		return nil, "", fmt.Errorf("auth session expired")
	}
	if !session.LastPollAt.IsZero() && time.Since(session.LastPollAt) < time.Duration(session.Authorization.Interval)*time.Second {
		oidcLoginSessions.Unlock()
		return session, "pending", nil
	}
	session.LastPollAt = time.Now()
	oidcLoginSessions.Unlock()

	token, pending, err := createKiroOIDCTokenFromDeviceCode(*session)
	if pending {
		return session, "pending", nil
	}
	if err != nil {
		oidcLoginSessions.Lock()
		if stored := oidcLoginSessions.byID[id]; stored != nil {
			stored.LastError = err.Error()
		}
		oidcLoginSessions.Unlock()
		return session, "", err
	}

	oidcLoginSessions.Lock()
	if stored := oidcLoginSessions.byID[id]; stored != nil {
		stored.CompletedToken = &token
		session = stored
	}
	oidcLoginSessions.Unlock()
	return session, "complete", nil
}

func createKiroOIDCTokenFromDeviceCode(session KiroOIDCLoginSession) (TokenData, bool, error) {
	body := map[string]any{
		"clientId":     session.Registration.ClientID,
		"clientSecret": session.Registration.ClientSecret,
		"grantType":    kiroOIDCDeviceGrantType,
		"deviceCode":   session.Authorization.DeviceCode,
	}
	rawBody, err := jsonStr.Marshal(body)
	if err != nil {
		return TokenData{}, false, err
	}
	req, err := http.NewRequest(http.MethodPost, oidcTokenEndpoint(kiroOIDCRegion), bytes.NewBuffer(rawBody))
	if err != nil {
		return TokenData{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := newOutboundHTTPClient().Do(req)
	if err != nil {
		return TokenData{}, false, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return TokenData{}, false, err
	}
	if resp.StatusCode != http.StatusOK {
		text := string(respBody)
		if isOIDCAuthorizationPending(text) {
			return TokenData{}, true, nil
		}
		return TokenData{}, false, fmt.Errorf("kiro OIDC token status: %d, response: %s", resp.StatusCode, text)
	}

	var created KiroOIDCRefreshResponse
	if err := jsonStr.Unmarshal(respBody, &created); err != nil {
		return TokenData{}, false, err
	}
	if created.AccessToken == "" || created.RefreshToken == "" {
		return TokenData{}, false, fmt.Errorf("kiro OIDC token response missing accessToken/refreshToken")
	}
	expiresAt := time.Now().Add(time.Duration(created.ExpiresIn) * time.Second).UTC().Format(time.RFC3339Nano)
	if created.ExpiresIn <= 0 {
		expiresAt = ""
	}

	return TokenData{
		AccessToken:        created.AccessToken,
		RefreshToken:       created.RefreshToken,
		ExpiresAt:          expiresAt,
		Region:             kiroOIDCRegion,
		StartURL:           kiroOIDCStartURL,
		OAuthFlow:          "DeviceCode",
		Scopes:             append([]string(nil), kiroOIDCScopes...),
		ClientID:           session.Registration.ClientID,
		ClientSecret:       session.Registration.ClientSecret,
		ClientSecretExpiry: session.Registration.ClientSecretExpiresRFC,
	}, false, nil
}

func isOIDCAuthorizationPending(text string) bool {
	text = strings.ToLower(text)
	return strings.Contains(text, "authorization_pending") || strings.Contains(text, "authorizationpending")
}

func oidcRegisterEndpoint(region string) string {
	return oidcFormatEndpoint(kiroOIDCRegisterEndpoint, region)
}

func oidcDeviceAuthEndpoint(region string) string {
	return oidcFormatEndpoint(kiroOIDCDeviceAuthEndpoint, region)
}

func oidcTokenEndpoint(region string) string {
	return oidcFormatEndpoint(kiroOIDCTokenEndpoint, region)
}

func oidcFormatEndpoint(endpoint, region string) string {
	region = strings.TrimSpace(region)
	if region == "" {
		region = kiroOIDCRegion
	}
	if strings.Contains(endpoint, "%s") {
		return fmt.Sprintf(endpoint, region)
	}
	return endpoint
}

func refreshKiroSocialToken(refreshToken string) (KiroRefreshResponse, error) {
	body, err := jsonStr.Marshal(map[string]string{"refreshToken": refreshToken})
	if err != nil {
		return KiroRefreshResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, kiroAuthRefreshEndpoint, bytes.NewBuffer(body))
	if err != nil {
		return KiroRefreshResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := newOutboundHTTPClient().Do(req)
	if err != nil {
		return KiroRefreshResponse{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return KiroRefreshResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return KiroRefreshResponse{}, fmt.Errorf("kiro refresh status: %d, response: %s", resp.StatusCode, string(respBody))
	}
	var refreshed KiroRefreshResponse
	if err := jsonStr.Unmarshal(respBody, &refreshed); err != nil {
		return KiroRefreshResponse{}, err
	}
	return refreshed, nil
}

func userFriendlyCreditsError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if strings.Contains(text, "AccessDeniedException") || strings.Contains(text, "bearer token included in the request is invalid") {
		return "Credits API недоступен для этого KAS token. Оставляю последнее сохраненное значение; актуальное значение можно взять через Kiro CLI /usage и внести вручную."
	}
	return "Не удалось обновить credits: " + text
}

func userFriendlyAccountCheckError(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	if isBlockedAccountErrorText(lower) {
		return "Аккаунт заблокирован Kiro/AWS. Проверь страницу Kiro usage/support или используй другой аккаунт."
	}
	return text
}

func isBlockedAccountErrorText(text string) bool {
	text = strings.ToLower(text)
	return strings.Contains(text, "temporarily is suspended") ||
		strings.Contains(text, "locked your account") ||
		strings.Contains(text, "заблокирован")
}

func disableBlockedAccount(account TokenAccount, message string) error {
	account.Token.Disabled = true
	account.Token.LastCheckError = message
	return persistTokenAccount(account)
}

func maybeRefreshCreditsAfterRequest(account TokenAccount, requestID string) {
	before := account.Token.CreditsRemaining
	go func(name string, before *float64) {
		account, err := selectTokenAccount(name)
		if err != nil {
			fmt.Printf("credits refresh after request failed for %s: %v\n", name, err)
			return
		}
		updated, err := updateAccountCredits(account)
		if err != nil {
			fmt.Printf("credits refresh after request failed for %s: %v\n", name, err)
		}
		if before != nil && updated.Token.CreditsRemaining != nil {
			updateRequestHistoryCreditsSpent(requestID, *before-*updated.Token.CreditsRemaining)
		}
	}(account.Name, before)
}

func startKASTokenRefreshScheduler() {
	go func() {
		refreshExpiredKASTokens()
		ticker := time.NewTicker(tokenRefreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			refreshExpiredKASTokens()
		}
	}()
}

func tokenExpiryError(token TokenData, now time.Time) error {
	if strings.TrimSpace(token.ExpiresAt) == "" {
		return nil
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, token.ExpiresAt)
	if err != nil {
		return nil
	}
	if now.Before(expiresAt) {
		return nil
	}
	return fmt.Errorf("KAS token expired at %s; получите новый KAS token через kiro-cli", token.ExpiresAt)
}

func checkAccountHealth(account TokenAccount) (map[string]any, error) {
	if err := tokenExpiryError(account.Token, time.Now()); err != nil {
		return nil, err
	}

	req := AnthropicRequest{
		Model:     "claude-3-5-haiku-20241022",
		MaxTokens: 8,
		Messages: []AnthropicRequestMessage{{
			Role:    "user",
			Content: "ping",
		}},
		Stream: false,
	}
	cwReq := buildCodeWhispererRequest(req, account.Token.ProfileArn)
	body, err := jsonStr.Marshal(cwReq)
	if err != nil {
		return nil, err
	}

	proxyReq, err := http.NewRequest(
		http.MethodPost,
		codeWhispererGenerateEndpoint,
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}
	proxyReq.Header.Set("Authorization", "Bearer "+account.Token.AccessToken)
	proxyReq.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := newOutboundHTTPClient().Do(proxyReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		message := userFriendlyAccountCheckError(string(respBody))
		if message == string(respBody) && strings.Contains(strings.ToLower(string(respBody)), "bearer token included in the request is invalid") {
			if diagnostic := accountAccessDiagnosticMessage(account); diagnostic != "" {
				message = diagnostic
			}
		}
		return map[string]any{
			"ok":         false,
			"status":     resp.StatusCode,
			"durationMs": time.Since(start).Milliseconds(),
			"message":    message,
		}, nil
	}

	return map[string]any{
		"ok":         true,
		"status":     resp.StatusCode,
		"durationMs": time.Since(start).Milliseconds(),
	}, nil
}

func accountAccessDiagnosticMessage(account TokenAccount) string {
	if _, err := fetchAvailableModels(account); err != nil {
		message := userFriendlyAccountCheckError(err.Error())
		if message != err.Error() || isBlockedAccountErrorText(message) {
			return message
		}
	}
	return ""
}

func updateAccountCredits(account TokenAccount) (TokenAccount, error) {
	remaining, err := fetchAccountCreditsRemaining(account)
	if err != nil {
		return account, err
	}

	account.Token.CreditsRemaining = &remaining
	if err := persistTokenAccount(account); err != nil {
		return account, err
	}
	return account, nil
}

func fetchAccountCreditsRemaining(account TokenAccount) (float64, error) {
	if err := tokenExpiryError(account.Token, time.Now()); err != nil {
		return 0, err
	}

	usageRequest := map[string]string{}
	if profileArn := strings.TrimSpace(account.Token.ProfileArn); profileArn != "" {
		usageRequest["profileArn"] = profileArn
	}
	body, err := jsonStr.Marshal(usageRequest)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest(http.MethodPost, codeWhispererUsageEndpoint, bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+account.Token.AccessToken)
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonCodeWhispererService.GetUsageLimits")

	resp, err := newOutboundHTTPClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("CodeWhisperer usage status: %d, response: %s", resp.StatusCode, string(respBody))
	}

	var usage CodeWhispererUsageResponse
	if err := jsonStr.Unmarshal(respBody, &usage); err != nil {
		return 0, err
	}
	return creditsRemainingFromUsage(usage)
}

func fetchAvailableModels(account TokenAccount) ([]CodeWhispererModel, error) {
	if err := tokenExpiryError(account.Token, time.Now()); err != nil {
		return nil, err
	}
	body, err := jsonStr.Marshal(map[string]string{"origin": "AI_EDITOR"})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, codeWhispererListModelsEndpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+account.Token.AccessToken)
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonCodeWhispererService.ListAvailableModels")

	resp, err := newOutboundHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		if message := userFriendlyAccountCheckError(string(respBody)); message != "" && message != string(respBody) {
			if err := disableBlockedAccount(account, message); err != nil {
				return nil, fmt.Errorf("%s; выключить аккаунт %s: %v", message, account.Name, err)
			}
			return nil, fmt.Errorf("%s", message)
		}
		return nil, fmt.Errorf("CodeWhisperer models status: %d, response: %s", resp.StatusCode, string(respBody))
	}

	var models CodeWhispererModelsResponse
	if err := jsonStr.Unmarshal(respBody, &models); err != nil {
		return nil, err
	}
	if len(models.Models) == 0 {
		return nil, fmt.Errorf("models not found")
	}
	return models.Models, nil
}

func creditsRemainingFromUsage(usage CodeWhispererUsageResponse) (float64, error) {
	for _, item := range usage.UsageBreakdownList {
		if item.ResourceType != "CREDIT" && !strings.EqualFold(item.DisplayName, "Credit") {
			continue
		}
		limit := item.UsageLimitWithPrecision
		if limit == 0 {
			limit = float64(item.UsageLimit)
		}
		current := item.CurrentUsageWithPrecision
		if current == 0 {
			current = float64(item.CurrentUsage)
		}
		return limit - current, nil
	}
	return 0, fmt.Errorf("credits usage not found")
}

func handleAdminUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	accounts, err := listTokenAccounts()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	result := map[string]any{
		"supported": true,
		"source":    "stored_accounts",
	}
	var remaining float64
	hasCredits := false
	for _, account := range accounts {
		if account.Token.Disabled {
			continue
		}
		if account.Token.CreditsRemaining == nil {
			continue
		}
		remaining += *account.Token.CreditsRemaining
		hasCredits = true
	}
	if hasCredits {
		result["creditsRemaining"] = remaining
	}
	writeJSON(w, http.StatusOK, result)
}

func handleAdminConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tokenDir":       getTokenDir(),
		"defaultFile":    getTokenFilePath(),
		"accountHeader":  "x-api-key: sk-*",
		"groupKeys":      adminSettingsResponse(loadAdminSettings()).Groups,
		"proxyEndpoint":  "/v1/messages",
		"adminEndpoint":  "/admin",
		"balanceSupport": true,
	})
}

func handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings, err := ensureAdminSettings()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"groups": accountGroupInfos(settings)})
	case http.MethodPost:
		var req AccountGroup
		if err := jsonStr.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		name := sanitizeGroupName(req.Name)
		settings, err := ensureAdminSettings()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, group := range settings.Groups {
			if group.Name == name {
				writeJSONError(w, http.StatusBadRequest, "group already exists")
				return
			}
		}
		key := strings.TrimSpace(req.APIKey)
		if key == "" {
			key = generateAPIKey()
		}
		settings.Groups = append(settings.Groups, AccountGroup{Name: name, APIKey: key})
		if err := saveAdminSettings(normalizeAdminSettings(settings)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"groups": accountGroupInfos(settings)})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handleAdminGroupAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/admin/api/groups/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSONError(w, http.StatusNotFound, "group not found")
		return
	}
	name := sanitizeGroupName(parts[0])
	settings, err := ensureAdminSettings()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	switch {
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "key":
		for i := range settings.Groups {
			if settings.Groups[i].Name != name {
				continue
			}
			settings.Groups[i].APIKey = generateAPIKey()
			if err := saveAdminSettings(normalizeAdminSettings(settings)); err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"groups": accountGroupInfos(settings)})
			return
		}
		writeJSONError(w, http.StatusNotFound, "group not found")
	case r.Method == http.MethodDelete && len(parts) == 1:
		accounts, err := listTokenAccounts()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, account := range accounts {
			if sanitizeGroupName(account.Token.Group) == name {
				writeJSONError(w, http.StatusBadRequest, "group has accounts")
				return
			}
		}
		next := settings.Groups[:0]
		found := false
		for _, group := range settings.Groups {
			if group.Name == name {
				found = true
				continue
			}
			next = append(next, group)
		}
		if !found {
			writeJSONError(w, http.StatusNotFound, "group not found")
			return
		}
		settings.Groups = next
		if err := saveAdminSettings(normalizeAdminSettings(settings)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"groups": accountGroupInfos(settings)})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings, err := ensureAdminSettings()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, adminSettingsResponse(settings))
	case http.MethodPut:
		current := loadAdminSettings()
		var settings AdminSettings
		if err := jsonStr.NewDecoder(r.Body).Decode(&settings); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		settings.AdminPasswordHash = current.AdminPasswordHash
		settings.Groups = current.Groups
		if err := saveAdminSettings(settings); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, adminSettingsResponse(settings))
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handleAdminAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	session, err := startKiroOIDCDeviceLogin()
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, adminAuthSessionResponse(session, "pending"))
}

func handleAdminAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/api/auth/"), "/")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "auth session id is required")
		return
	}

	session, status, err := pollKiroOIDCLoginSession(id)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, adminAuthSessionResponse(session, status))
}

func adminAuthSessionResponse(session *KiroOIDCLoginSession, status string) map[string]any {
	resp := map[string]any{
		"id":                      session.ID,
		"status":                  status,
		"userCode":                session.Authorization.UserCode,
		"verificationUri":         session.Authorization.VerificationURI,
		"verificationUriComplete": session.Authorization.VerificationURIComplete,
		"interval":                session.Authorization.Interval,
		"expiresAt":               session.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if session.LastError != "" {
		resp["error"] = session.LastError
	}
	if session.CompletedToken != nil {
		resp["kasJson"] = adminKASJSONFromToken(*session.CompletedToken)
	}
	return resp
}

func adminKASJSONFromToken(token TokenData) map[string]any {
	body := map[string]any{
		"access_token":             token.AccessToken,
		"refresh_token":            token.RefreshToken,
		"expires_at":               token.ExpiresAt,
		"region":                   token.Region,
		"start_url":                token.StartURL,
		"oauth_flow":               token.OAuthFlow,
		"scopes":                   token.Scopes,
		"client_id":                token.ClientID,
		"client_secret":            token.ClientSecret,
		"client_secret_expires_at": token.ClientSecretExpiry,
	}
	if token.ProfileArn != "" {
		body["profile_arn"] = token.ProfileArn
	}
	return body
}

func handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		accounts, err := listTokenAccounts()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		infos := make([]AccountInfo, 0, len(accounts))
		for _, account := range accounts {
			infos = append(infos, tokenAccountInfo(account, ""))
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"accounts": infos,
			"tokenDir": getTokenDir(),
		})
	case http.MethodPost:
		var req SaveAccountRequest
		if err := jsonStr.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		enabled := true
		if existing, err := selectTokenAccount(req.Name); err == nil {
			enabled = !existing.Token.Disabled
		}
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		req.Group = sanitizeGroupName(req.Group)
		settings, err := ensureAdminSettings()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		groupExists := false
		for _, group := range settings.Groups {
			if group.Name == req.Group {
				groupExists = true
				break
			}
		}
		if !groupExists {
			writeJSONError(w, http.StatusBadRequest, "group not found")
			return
		}
		account, err := writeTokenAccount(req.Name, TokenData{
			AccessToken:        req.AccessToken,
			RefreshToken:       req.RefreshToken,
			ExpiresAt:          req.ExpiresAt,
			ProfileArn:         req.ProfileArn,
			Region:             req.Region,
			StartURL:           req.StartURL,
			OAuthFlow:          req.OAuthFlow,
			Scopes:             req.Scopes,
			ClientID:           req.ClientID,
			ClientSecret:       req.ClientSecret,
			ClientSecretExpiry: req.ClientSecretExpiry,
			APIKey:             req.APIKey,
			Group:              req.Group,
			Disabled:           !enabled,
			RPS:                req.RPS,
			Concurrency:        req.Concurrency,
			CreditsRemaining:   req.CreditsRemaining,
			LastTestDurationMs: req.LastTestDurationMs,
			LastCheckError:     req.LastCheckError,
		})
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeJSON(w, http.StatusCreated, tokenAccountInfo(account, ""))
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handleAdminAccountAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/admin/api/accounts/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSONError(w, http.StatusNotFound, "account not found")
		return
	}

	name := parts[0]
	account, err := selectTokenAccount(name)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}

	if r.Method == http.MethodDelete && len(parts) == 1 {
		if err := os.Remove(account.Path); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": account.Name})
		return
	}

	if r.Method != http.MethodPost || len(parts) != 2 {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	switch parts[1] {
	case "toggle":
		account.Token.Disabled = !account.Token.Disabled
		if err := persistTokenAccount(account); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, tokenAccountInfo(account, ""))
	case "check":
		result, err := checkAccountHealth(account)
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, err.Error())
			return
		}
		if ok, _ := result["ok"].(bool); ok {
			account.Token.LastCheckError = ""
		} else if message, _ := result["message"].(string); message != "" {
			account.Token.LastCheckError = message
			if isBlockedAccountErrorText(message) {
				account.Token.Disabled = true
			}
		}
		if duration, ok := result["durationMs"].(int64); ok {
			account.Token.LastTestDurationMs = &duration
			if err := persistTokenAccount(account); err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
			result["lastTestDurationMs"] = duration
		} else if account.Token.LastCheckError != "" {
			if err := persistTokenAccount(account); err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		writeJSON(w, http.StatusOK, result)
	case "credits":
		updated, err := updateAccountCredits(account)
		if err != nil {
			info := tokenAccountInfo(account, "")
			info.CreditsRefreshError = userFriendlyCreditsError(err)
			info.Status = "error"
			info.StatusMessage = info.CreditsRefreshError
			writeJSON(w, http.StatusOK, info)
			return
		}
		writeJSON(w, http.StatusOK, tokenAccountInfo(updated, ""))
	case "token":
		if err := refreshKASToken(account); err != nil {
			info := tokenAccountInfo(account, "")
			info.TokenRefreshError = "Не удалось обновить KAS token: " + err.Error()
			info.Status = "error"
			info.StatusMessage = info.TokenRefreshError
			writeJSON(w, http.StatusOK, info)
			return
		}
		updated, err := selectTokenAccount(account.Name)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, tokenAccountInfo(updated, ""))
	default:
		writeJSONError(w, http.StatusNotFound, "unknown action")
	}
}

func handleAdminBalance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	handleAdminUsage(w, r)
}

func handleAdminUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(adminHTML))
}

// handleStreamRequest 处理流式请求
func handleStreamRequest(w http.ResponseWriter, anthropicReq AnthropicRequest, account TokenAccount) (int, int, int, string) {
	// 设置SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return http.StatusInternalServerError, 0, 0, "streaming unsupported"
	}

	messageId := fmt.Sprintf("msg_%s", time.Now().Format("20060102150405"))

	// 构建 CodeWhisperer 请求
	cwReq := buildCodeWhispererRequest(anthropicReq, account.Token.ProfileArn)

	// 序列化请求体
	cwReqBody, err := jsonStr.Marshal(cwReq)
	if err != nil {
		sendErrorEvent(w, flusher, "序列化请求失败", err)
		return http.StatusInternalServerError, 0, 0, err.Error()
	}

	// fmt.Printf("CodeWhisperer 流式请求体:\n%s\n", string(cwReqBody))

	// 创建流式请求
	proxyReq, err := http.NewRequest(
		http.MethodPost,
		codeWhispererGenerateEndpoint,
		bytes.NewBuffer(cwReqBody),
	)
	if err != nil {
		sendErrorEvent(w, flusher, "创建代理请求失败", err)
		return http.StatusInternalServerError, 0, 0, err.Error()
	}

	// 设置请求头
	proxyReq.Header.Set("Authorization", "Bearer "+account.Token.AccessToken)
	proxyReq.Header.Set("Content-Type", "application/json")
	proxyReq.Header.Set("Accept", "text/event-stream")

	// 发送请求
	client := newOutboundHTTPClient()

	resp, err := client.Do(proxyReq)
	if err != nil {
		sendErrorEvent(w, flusher, "CodeWhisperer reqeust error", fmt.Errorf("reqeust error: %s", err.Error()))
		return http.StatusBadGateway, 0, 0, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("CodeWhisperer 响应错误，状态码: %d, 响应: %s\n", resp.StatusCode, string(body))
		sendErrorEvent(w, flusher, "error", fmt.Errorf("状态码: %d", resp.StatusCode))

		if resp.StatusCode == 403 {
			sendErrorEvent(w, flusher, "error", fmt.Errorf("CodeWhisperer token invalid; получите новый KAS token через kiro-cli"))
		} else {
			sendErrorEvent(w, flusher, "error", fmt.Errorf("CodeWhisperer Error: %s ", string(body)))
		}
		return resp.StatusCode, len(getMessageContent(anthropicReq.Messages[len(anthropicReq.Messages)-1].Content)), 0, string(body)
	}

	// 先读取整个响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		sendErrorEvent(w, flusher, "error", fmt.Errorf("CodeWhisperer Error 读取响应失败"))
		return http.StatusBadGateway, 0, 0, err.Error()
	}

	// os.WriteFile(messageId+"response.raw", respBody, 0644)

	// 使用新的CodeWhisperer解析器
	events := parser.ParseEvents(respBody)

	if len(events) > 0 {

		// 发送开始事件
		messageStart := map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"id":            messageId,
				"type":          "message",
				"role":          "assistant",
				"content":       []any{},
				"model":         anthropicReq.Model,
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage": map[string]any{
					"input_tokens":  len(getMessageContent(anthropicReq.Messages[0].Content)),
					"output_tokens": 1,
				},
			},
		}
		sendSSEEvent(w, flusher, "message_start", messageStart)
		sendSSEEvent(w, flusher, "ping", map[string]string{
			"type": "ping",
		})

		contentBlockStart := map[string]any{
			"content_block": map[string]any{
				"text": "",
				"type": "text"},
			"index": 0, "type": "content_block_start",
		}

		sendSSEEvent(w, flusher, "content_block_start", contentBlockStart)
		// 处理解析出的事件

		outputTokens := 0
		for _, e := range events {
			sendSSEEvent(w, flusher, e.Event, e.Data)

			if e.Event == "content_block_delta" {
				outputTokens += len(getStreamDeltaText(e.Data))
			}
		}

		contentBlockStop := map[string]any{
			"index": 0,
			"type":  "content_block_stop",
		}
		sendSSEEvent(w, flusher, "content_block_stop", contentBlockStop)

		contentBlockStopReason := map[string]any{
			"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]any{
				"output_tokens": outputTokens,
			},
		}
		sendSSEEvent(w, flusher, "message_delta", contentBlockStopReason)

		messageStop := map[string]any{
			"type": "message_stop",
		}
		sendSSEEvent(w, flusher, "message_stop", messageStop)
		return http.StatusOK, len(getMessageContent(anthropicReq.Messages[len(anthropicReq.Messages)-1].Content)), outputTokens, ""
	}
	return http.StatusOK, len(getMessageContent(anthropicReq.Messages[len(anthropicReq.Messages)-1].Content)), 0, ""
}

// handleNonStreamRequest 处理非流式请求
func handleNonStreamRequest(w http.ResponseWriter, anthropicReq AnthropicRequest, account TokenAccount) (int, int, int, string) {
	// 构建 CodeWhisperer 请求
	cwReq := buildCodeWhispererRequest(anthropicReq, account.Token.ProfileArn)

	// 序列化请求体
	cwReqBody, err := jsonStr.Marshal(cwReq)
	if err != nil {
		fmt.Printf("错误: 序列化请求失败: %v\n", err)
		http.Error(w, fmt.Sprintf("序列化请求失败: %v", err), http.StatusInternalServerError)
		return http.StatusInternalServerError, 0, 0, err.Error()
	}

	// fmt.Printf("CodeWhisperer 请求体:\n%s\n", string(cwReqBody))

	// 创建请求
	proxyReq, err := http.NewRequest(
		http.MethodPost,
		codeWhispererGenerateEndpoint,
		bytes.NewBuffer(cwReqBody),
	)
	if err != nil {
		fmt.Printf("错误: 创建代理请求失败: %v\n", err)
		http.Error(w, fmt.Sprintf("创建代理请求失败: %v", err), http.StatusInternalServerError)
		return http.StatusInternalServerError, 0, 0, err.Error()
	}

	// 设置请求头
	proxyReq.Header.Set("Authorization", "Bearer "+account.Token.AccessToken)
	proxyReq.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := newOutboundHTTPClient()

	resp, err := client.Do(proxyReq)
	if err != nil {
		fmt.Printf("错误: 发送请求失败: %v\n", err)
		http.Error(w, fmt.Sprintf("发送请求失败: %v", err), http.StatusInternalServerError)
		return http.StatusBadGateway, 0, 0, err.Error()
	}
	defer resp.Body.Close()

	// 读取响应
	cwRespBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("错误: 读取响应失败: %v\n", err)
		http.Error(w, fmt.Sprintf("读取响应失败: %v", err), http.StatusInternalServerError)
		return http.StatusBadGateway, 0, 0, err.Error()
	}

	if resp.StatusCode == http.StatusForbidden {
		errText := fmt.Sprintf("CodeWhisperer status: %d, response: %s", resp.StatusCode, string(cwRespBody))
		http.Error(w, errText, http.StatusBadGateway)
		return resp.StatusCode, len(cwReq.ConversationState.CurrentMessage.UserInputMessage.Content), 0, errText
	}
	if resp.StatusCode != http.StatusOK {
		errText := fmt.Sprintf("CodeWhisperer status: %d, response: %s", resp.StatusCode, string(cwRespBody))
		http.Error(w, errText, http.StatusBadGateway)
		return resp.StatusCode, len(cwReq.ConversationState.CurrentMessage.UserInputMessage.Content), 0, errText
	}

	// fmt.Printf("CodeWhisperer 响应体:\n%s\n", string(cwRespBody))

	respBodyStr := string(cwRespBody)

	events := parser.ParseEvents(cwRespBody)

	context := ""
	toolName := ""
	toolUseId := ""

	contexts := []map[string]any{}

	partialJsonStr := ""
	for _, event := range events {
		if event.Data != nil {
			if dataMap, ok := event.Data.(map[string]any); ok {
				switch dataMap["type"] {
				case "content_block_start":
					context = ""
				case "content_block_delta":
					if delta, ok := dataMap["delta"]; ok {

						if deltaMap, ok := delta.(map[string]any); ok {
							switch deltaMap["type"] {
							case "text_delta":
								if text, ok := deltaMap["text"]; ok {
									context += text.(string)
								}
							case "input_json_delta":
								toolUseId = deltaMap["id"].(string)
								toolName = deltaMap["name"].(string)
								if partial_json, ok := deltaMap["partial_json"]; ok {
									if strPtr, ok := partial_json.(*string); ok && strPtr != nil {
										partialJsonStr = partialJsonStr + *strPtr
									} else if str, ok := partial_json.(string); ok {
										partialJsonStr = partialJsonStr + str
									} else {
										log.Println("partial_json is not string or *string")
									}
								} else {
									log.Println("partial_json not found")
								}

							}
						}
					}

				case "content_block_stop":
					if index, ok := dataMap["index"]; ok {
						switch index {
						case 1:
							toolInput := map[string]interface{}{}
							if err := jsonStr.Unmarshal([]byte(partialJsonStr), &toolInput); err != nil {
								log.Printf("json unmarshal error:%s", err.Error())
							}

							contexts = append(contexts, map[string]interface{}{
								"type":  "tool_use",
								"id":    toolUseId,
								"name":  toolName,
								"input": toolInput,
							})
						case 0:
							contexts = append(contexts, map[string]interface{}{
								"text": context,
								"type": "text",
							})
						}
					}
				}

			}
		}
	}

	// 回退：如果已累积到文本但未收到 content_block_stop(index=0)，也要返回文本
	if len(contexts) == 0 && strings.TrimSpace(context) != "" {
		contexts = append(contexts, map[string]any{
			"type": "text",
			"text": context,
		})
	}

	// 检查是否是错误响应
	if strings.Contains(string(cwRespBody), "Improperly formed request.") {
		fmt.Printf("错误: CodeWhisperer返回格式错误: %s\n", respBodyStr)
		http.Error(w, fmt.Sprintf("请求格式错误: %s", respBodyStr), http.StatusBadRequest)
		return http.StatusBadRequest, len(cwReq.ConversationState.CurrentMessage.UserInputMessage.Content), 0, respBodyStr
	}

	// 构建 Anthropic 响应
	anthropicResp := map[string]any{
		"content":       contexts,
		"model":         anthropicReq.Model,
		"role":          "assistant",
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"type":          "message",
		"usage": map[string]any{
			"input_tokens":  len(cwReq.ConversationState.CurrentMessage.UserInputMessage.Content),
			"output_tokens": len(context),
		},
	}

	// 发送响应
	w.Header().Set("Content-Type", "application/json")
	jsonStr.NewEncoder(w).Encode(anthropicResp)
	return http.StatusOK, len(cwReq.ConversationState.CurrentMessage.UserInputMessage.Content), len(context), ""
}

// sendSSEEvent 发送 SSE 事件
func sendSSEEvent(w http.ResponseWriter, flusher http.Flusher, eventType string, data any) {

	json, err := jsonStr.Marshal(data)
	if err != nil {
		return
	}

	fmt.Fprintf(w, "event: %s\n", eventType)
	fmt.Fprintf(w, "data: %s\n\n", string(json))
	flusher.Flush()

}

// sendErrorEvent 发送错误事件
func sendErrorEvent(w http.ResponseWriter, flusher http.Flusher, message string, err error) {
	errorResp := map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    "overloaded_error",
			"message": message,
		},
	}

	// data: {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}

	sendSSEEvent(w, flusher, "error", errorResp)
}

const adminLoginHTML = `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vibecode API login</title>
  <style>
    :root { --bg:#f5f7f8; --panel:#fff; --text:#172026; --muted:#63717b; --line:#d9e0e4; --accent:#1d7f64; --danger:#b44747; }
    * { box-sizing:border-box; }
    body { min-height:100vh; margin:0; display:grid; place-items:center; background:var(--bg); color:var(--text); font:14px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(380px, calc(100vw - 32px)); background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:22px; }
    h1 { margin:0 0 16px; font-size:22px; letter-spacing:0; }
    label { display:grid; gap:6px; color:var(--muted); font-size:12px; font-weight:650; margin-bottom:14px; }
    input { width:100%; border:1px solid var(--line); border-radius:6px; padding:10px; font:inherit; color:var(--text); background:var(--panel); }
    button { width:100%; min-height:36px; border:1px solid var(--accent); background:var(--accent); color:#fff; border-radius:6px; padding:8px 10px; font:inherit; cursor:pointer; }
  </style>
</head>
<body>
  <main>
    <h1>Vibecode API</h1>
    <form method="post" action="/admin/login">
      <label>Пароль панели<input name="password" type="password" autocomplete="current-password" autofocus required></label>
      <button type="submit">Войти</button>
    </form>
  </main>
</body>
</html>`

const adminHTML = `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vibecode API</title>
  <script>
    (()=>{try{const t=localStorage.getItem('kiro-admin.theme')||'light'; document.documentElement.dataset.theme=t}catch(_){}})();
  </script>
  <style>
    :root { --bg:#f5f7f8; --panel:#fff; --text:#172026; --muted:#63717b; --line:#d9e0e4; --accent:#1d7f64; --danger:#b44747; --warn:#9b6a17; --code:#eef2f3; --code-text:#263139; }
    [data-theme="dark"] { --bg:#111827; --panel:#172235; --text:#eef4ff; --muted:#b8c7dd; --line:#2e3d56; --accent:#6aa7ff; --danger:#ff7a7a; --warn:#f0c36a; --code:#22314a; --code-text:#e7f0ff; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font:14px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    header { display:flex; align-items:center; justify-content:space-between; gap:16px; padding:20px 28px; border-bottom:1px solid var(--line); background:var(--panel); }
    h1 { margin:0; font-size:22px; line-height:1.1; letter-spacing:0; }
    h2 { margin:0 0 14px; font-size:16px; letter-spacing:0; }
    h3 { margin:14px 0 8px; font-size:13px; color:var(--muted); }
    main { padding:18px 28px 32px; max-width:1380px; margin:0 auto; }
    section { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
    .top { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    .section-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:14px; }
    .section-head h2 { margin:0; }
    .section-tools { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
    .grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin-bottom:18px; }
    .metric { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }
    .metric b { display:block; font-size:22px; margin-top:4px; }
    .muted { color:var(--muted); }
    code, pre { background:var(--code); border-radius:6px; color:var(--code-text); font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
    code { padding:2px 5px; overflow-wrap:anywhere; }
    pre { padding:10px; overflow:auto; white-space:pre-wrap; }
    table { width:100%; border-collapse:collapse; table-layout:fixed; }
    th, td { padding:9px 7px; border-bottom:1px solid var(--line); text-align:left; vertical-align:middle; word-break:break-word; }
    th { color:var(--muted); font-size:12px; font-weight:650; }
    .accounts-table th:nth-child(3), .accounts-table td:nth-child(3) { width:22ch; white-space:nowrap; }
    .accounts-table th:nth-child(4), .accounts-table td:nth-child(4) { width:92px; }
    .accounts-table th:nth-child(5), .accounts-table td:nth-child(5) { width:10ch; white-space:nowrap; }
    .accounts-table th:nth-child(6), .accounts-table td:nth-child(6) { width:136px; }
    button, select { min-height:32px; border:1px solid var(--line); background:var(--panel); color:var(--text); border-radius:6px; padding:6px 10px; font:inherit; cursor:pointer; }
    button:hover { border-color:var(--accent); color:var(--accent); }
    button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
    button.danger:hover { border-color:var(--danger); color:var(--danger); }
    button.icon { width:28px; min-height:28px; padding:0; border-radius:50%; line-height:1; }
    label { display:grid; gap:6px; color:var(--muted); font-size:12px; font-weight:650; margin-bottom:10px; }
    input, textarea { width:100%; border:1px solid var(--line); border-radius:6px; padding:9px 10px; font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; color:var(--text); background:var(--panel); }
    input::placeholder, textarea::placeholder { color:var(--muted); opacity:.8; }
    textarea { min-height:88px; resize:vertical; }
    .actions { display:flex; gap:6px; flex-wrap:wrap; }
    .account-actions { display:flex; flex-direction:column; align-items:stretch; gap:4px; }
    .account-actions button { min-height:26px; padding:3px 7px; font-size:12px; line-height:1.15; }
    .account-head { display:grid; grid-template-columns:auto minmax(0,1fr); align-items:flex-start; gap:8px; }
    .power-toggle { position:relative; width:36px; min-height:22px; margin-top:1px; padding:0; border-radius:999px; background:var(--code); transition:background-color .2s ease, border-color .2s ease, box-shadow .2s ease, transform .12s ease; }
    .power-toggle::after { content:""; position:absolute; top:3px; left:3px; width:14px; height:14px; border-radius:50%; background:var(--muted); transition:transform .22s cubic-bezier(.22,1,.36,1), background-color .2s ease, box-shadow .2s ease; }
    .power-toggle:hover { box-shadow:0 0 0 3px color-mix(in srgb, var(--accent) 14%, transparent); }
    .power-toggle:active { transform:scale(.96); }
    .power-toggle:focus-visible { outline:0; box-shadow:0 0 0 3px color-mix(in srgb, var(--accent) 26%, transparent); }
    .power-toggle.on { border-color:var(--accent); background:var(--accent); }
    .power-toggle.on::after { transform:translateX(14px); background:#fff; box-shadow:0 1px 3px rgba(0,0,0,.2); }
    .power-toggle.off { border-color:var(--line); }
    .power-toggle.off::after { background:var(--muted); }
    .inline { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
    .inline.credit-inline { gap:5px; flex-wrap:nowrap; }
    .key-inline { display:flex; align-items:center; gap:5px; min-width:0; }
    .key-inline code { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .status { display:inline-flex; align-items:center; gap:6px; font-size:12px; color:var(--muted); }
    .dot { width:8px; height:8px; border-radius:50%; background:var(--line); }
    .status.active .dot { background:var(--accent); }
    .status.error .dot { background:var(--danger); }
    .notice { margin-top:12px; padding:10px 12px; border:1px solid var(--line); background:var(--code); color:var(--warn); border-radius:8px; }
    .tabs { display:flex; gap:6px; margin-bottom:12px; }
    .tab.active { background:var(--accent); color:#fff; border-color:var(--accent); }
    .view-tabs { display:flex; gap:8px; margin:0 0 14px; flex-wrap:wrap; }
    .view-tab.active { background:var(--accent); color:#fff; border-color:var(--accent); }
    .time-toolbar { position:relative; display:flex; align-items:center; justify-content:flex-end; gap:6px; margin:0 0 14px; }
    .time-button { display:inline-flex; align-items:center; gap:7px; max-width:260px; min-height:30px; padding:5px 9px; font-size:12px; }
    .time-button span { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .time-menu { position:absolute; z-index:10; right:0; top:36px; width:min(360px, calc(100vw - 32px)); display:none; border:1px solid var(--line); border-radius:8px; background:var(--panel); box-shadow:0 18px 48px rgba(0,0,0,.18); padding:10px; }
    .time-toolbar.open .time-menu { display:block; }
    .time-presets { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:6px; margin-bottom:10px; }
    .time-presets button { min-height:28px; padding:4px 7px; font-size:12px; }
    .time-presets button.active { border-color:var(--accent); color:#fff; background:var(--accent); }
    .time-custom { display:grid; grid-template-columns:1fr 1fr auto; gap:8px; align-items:end; }
    .time-custom label { margin:0; }
    .time-custom input { min-height:28px; padding:5px 8px; font-size:12px; }
    .view-panel.hide { display:none; }
    .hide { display:none; }
    .modal { position:fixed; inset:0; z-index:20; display:none; align-items:center; justify-content:center; padding:24px; background:rgba(10,18,30,.58); }
    .modal.open { display:flex; }
    .modal-panel { width:min(1120px,100%); max-height:calc(100vh - 48px); overflow:auto; background:var(--panel); border:1px solid var(--line); border-radius:8px; box-shadow:0 24px 60px rgba(0,0,0,.28); padding:18px; }
    .models-panel { width:min(420px,100%); }
    .models-list { display:grid; gap:7px; margin-top:10px; }
    .model-row { display:grid; gap:3px; padding:8px 10px; border:1px solid var(--line); border-radius:6px; background:var(--code); }
    .model-row code { padding:0; background:transparent; font-size:12px; }
    .model-meta { color:var(--muted); font-size:12px; }
    .modal-grid { display:grid; grid-template-columns:minmax(0,1fr) minmax(320px,.85fr); gap:18px; align-items:start; }
    .auth-panel { display:grid; gap:10px; margin-bottom:16px; }
    .auth-box { display:grid; width:100%; min-width:0; box-sizing:border-box; gap:8px; padding:10px; border:1px solid var(--line); border-radius:6px; background:var(--code); }
    .auth-box.hide { display:none; }
    .auth-actions { display:grid; grid-template-columns:auto minmax(0,1fr); gap:8px; align-items:center; }
    #authStatus, #authLink { min-width:0; overflow-wrap:anywhere; }
    #message { min-height:22px; color:var(--muted); }
    @media (max-width:980px) { main { padding:16px; } .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } header { align-items:flex-start; flex-direction:column; padding:18px; } .modal-grid { grid-template-columns:1fr; } }
    @media (max-width:680px) { .grid { grid-template-columns:1fr; } table,thead,tbody,th,td,tr { display:block; } thead { display:none; } tr { border-bottom:1px solid var(--line); padding:10px 0; } td { border:0; padding:5px 0; } .accounts-table th:nth-child(n), .accounts-table td:nth-child(n) { width:auto; white-space:normal; } td::before { content:attr(data-label); display:block; color:var(--muted); font-size:11px; font-weight:700; } }
  </style>
</head>
<body>
  <header>
    <div><h1>Vibecode API</h1><div id="message">Loading...</div></div>
    <div class="top"><select id="dataRefreshMode" title="Автообновление"><option value="one_second" data-i="dataRefreshOneSecond">Автообновление: 1 сек</option><option value="ten_seconds" data-i="dataRefreshTenSeconds">Автообновление: 10 сек</option><option value="one_minute" data-i="dataRefreshOneMinute">Автообновление: 1 мин</option></select><select id="lang"><option value="ru">Русский</option><option value="en">English</option><option value="zh">中文</option></select><select id="theme"><option value="light" data-i="themeLight">Светлая</option><option value="dark" data-i="themeDark">Темная</option></select><button type="button" onclick="openSettingsModal()" data-i="settings">Настройки</button><form method="post" action="/admin/logout" style="margin:0"><button type="submit">Выйти</button></form></div>
  </header>
  <main>
    <div class="grid">
      <div class="metric"><span data-i="accounts">Аккаунты</span><b id="accountsMetric">0</b></div>
      <div class="metric"><span data-i="credits">Credits</span><b id="creditsMetric">?</b></div>
      <div class="metric"><span data-i="requests">Запросы</span><b id="requestsMetric">0</b></div>
    </div>
    <div class="time-toolbar" id="timeRangePicker">
      <button class="time-button" id="timeRangeButton" type="button" title="Диапазон времени"><span id="timeRangeLabel">Все даты</span> ▾</button>
      <button class="icon" id="refreshNow" type="button" title="Обновить">↻</button>
      <span id="statsResetNote" class="muted"></span>
      <div class="time-menu" id="timeRangeMenu">
        <div class="time-presets">
          <button type="button" data-range="last_5m">Last 5m</button>
          <button type="button" data-range="last_15m">Last 15m</button>
          <button type="button" data-range="last_1h">Last 1h</button>
          <button type="button" data-range="last_6h">Last 6h</button>
          <button type="button" data-range="last_24h">Last 24h</button>
          <button type="button" data-range="last_7d">Last 7d</button>
          <button type="button" data-range="today">Today</button>
          <button type="button" data-range="yesterday">Yesterday</button>
          <button type="button" data-range="all">All</button>
        </div>
        <div class="time-custom">
          <label>From<input id="historyFrom" type="datetime-local"></label>
          <label>To<input id="historyTo" type="datetime-local"></label>
          <button class="primary" id="applyHistoryRange" type="button">Apply</button>
        </div>
      </div>
    </div>
    <div class="view-tabs"><button class="view-tab active" data-view="accounts" type="button">Аккаунты</button><button class="view-tab" data-view="groups" type="button">Группы</button><button class="view-tab" data-view="history" type="button">История</button><button class="view-tab" data-view="stats" type="button">Статистика</button></div>
    <section id="accountsView" class="view-panel">
      <div class="section-head">
        <h2 data-i="accounts">Аккаунты</h2>
        <div class="section-tools">
          <select id="accountGroupFilter" title="Группа"></select>
          <select id="accountSort">
            <option value="name" data-i="sortByName">По названию</option>
            <option value="credits" data-i="sortByCredits">По credits</option>
            <option value="latency" data-i="sortByLatency">По задержке</option>
          </select>
          <button id="accountSortDir" title="Порядок сортировки">↑</button>
          <button class="primary" onclick="openAccountModal()" data-i="add">Добавить</button>
        </div>
      </div>
      <div class="muted">Proxy: <code>/v1/messages</code>, key header: <code>x-api-key: sk-*</code></div>
      <table class="accounts-table">
        <thead><tr><th data-i="name">Имя</th><th>sk-*</th><th data-i="tokenUpdatedAt">Дата обнов. токена</th><th data-i="credits">Credits</th><th data-i="latency">Задержка</th><th data-i="actions">Действия</th></tr></thead>
        <tbody id="accountsBody"></tbody>
      </table>
    </section>
    <section id="groupsView" class="view-panel hide" style="margin-top:18px">
      <div class="section-head">
        <h2>Группы</h2>
        <form id="groupForm" class="section-tools">
          <input name="name" placeholder="team-a" autocomplete="off" required>
          <button class="primary" type="submit">Добавить группу</button>
        </form>
      </div>
      <div class="notice">Каждая группа имеет свой sk-ключ. Запросы по ключу группы балансируются только между аккаунтами этой группы; баланс считается как сумма credits группы.</div>
      <table>
        <thead><tr><th>Группа</th><th>sk-ключ</th><th>Аккаунты</th><th>Credits</th><th data-i="actions">Действия</th></tr></thead>
        <tbody id="groupsBody"></tbody>
      </table>
    </section>
    <section id="historyView" class="view-panel hide" style="margin-top:18px">
      <div class="section-head">
        <h2 data-i="history">История запросов</h2>
        <button class="danger" type="button" onclick="resetHistory()">Сбросить историю</button>
      </div>
      <table>
        <thead><tr><th data-i="time">Время</th><th data-i="account">Аккаунт</th><th data-i="model">Модель</th><th data-i="status">Статус</th><th>ms</th><th data-i="inputOutput">Input / Output</th><th data-i="creditsSpent">Credits потрачено</th><th data-i="error">Ошибка</th></tr></thead>
        <tbody id="historyBody"></tbody>
      </table>
    </section>
    <section id="statsView" class="view-panel hide" style="margin-top:18px">
      <div class="section-head">
        <h2>Статистика</h2>
        <button class="danger" type="button" onclick="resetStats()">Сбросить статистику</button>
      </div>
      <div class="grid">
        <div class="metric"><span>Успешные</span><b id="successMetric">0</b></div>
        <div class="metric"><span>Ошибки</span><b id="failedMetric">0</b></div>
        <div class="metric"><span>Всего</span><b id="totalMetric">0</b></div>
      </div>
      <h3>Коды ответов</h3>
      <div id="statusStats" class="models-list"></div>
      <h3>Ошибки</h3>
      <div id="errorStats" class="models-list"></div>
      <h3>Аккаунты</h3>
      <table>
        <thead><tr><th>Аккаунт</th><th>Всего</th><th>OK</th><th>FAIL</th><th>Fail %</th><th>Avg ms</th><th>Последняя ошибка</th></tr></thead>
        <tbody id="accountStatsBody"></tbody>
      </table>
    </section>
  </main>
  <div class="modal" id="accountModal" role="dialog" aria-modal="true" aria-labelledby="accountModalTitle">
    <div class="modal-panel">
      <div class="section-head">
        <h2 id="accountModalTitle" data-i="addAccount">Добавить аккаунт</h2>
        <button type="button" onclick="closeAccountModal()" data-i="close">Закрыть</button>
      </div>
      <div class="modal-grid">
        <section>
          <h2 data-i="saveToken">Добавить KAS token</h2>
          <form id="accountForm">
            <label><span data-i="name">Имя</span><input name="name" placeholder="work" autocomplete="off" required></label>
            <label><span data-i="kasJson">KAS JSON из CLI</span><textarea name="kasJson" spellcheck="false" placeholder='{"access_token":"...","refresh_token":"...","expires_at":"...","profile_arn":"optional","oauth_flow":"PKCE"}' required></textarea></label>
            <label><span data-i="proxyKey">Proxy key sk-*</span><input name="apiKey" placeholder="оставь пустым для генерации" autocomplete="off"></label>
            <label>Группа<select name="group" id="accountGroupSelect"></select></label>
            <label>RPS<input name="rps" type="number" min="0.1" step="0.1" value="2"></label>
            <label>Concurrency<input name="concurrency" type="number" min="1" step="1" value="4"></label>
            <label><span data-i="creditsManual">Credits осталось (если знаешь)</span><input name="creditsRemaining" type="number" min="0" step="0.01" placeholder="49.89"></label>
            <button class="primary" type="submit" data-i="save">Сохранить</button>
          </form>
        </section>
        <section>
          <div class="auth-panel">
            <h2>Авторизация</h2>
            <div class="auth-actions"><button class="primary" type="button" onclick="startAdminAuthorization()">Авторизация</button><span class="muted">Получит KAS JSON через AWS Builder ID device flow и вставит его в форму слева</span></div>
            <div id="authBox" class="auth-box hide">
              <div id="authStatus" class="muted"></div>
              <div id="authLink"></div>
            </div>
          </div>
          <h2 data-i="howTo">Как получить валидный KAS token</h2>
          <div class="tabs"><button class="tab active" data-os="macos">macOS</button><button class="tab" data-os="linux">Linux</button><button class="tab" data-os="windows">Windows</button></div>
          <div id="helpText"></div>
        </section>
      </div>
    </div>
  </div>
  <div class="modal" id="settingsModal" role="dialog" aria-modal="true" aria-labelledby="settingsModalTitle">
    <div class="modal-panel">
      <div class="section-head">
        <h2 id="settingsModalTitle" data-i="settings">Настройки</h2>
        <button type="button" onclick="closeSettingsModal()" data-i="close">Закрыть</button>
      </div>
      <div class="notice">Общие sk-ключи теперь находятся во вкладке “Группы”. Credits обновляются автоматически после каждого запроса, баланс считается отдельно по каждой группе.</div>
      <section style="margin-top:14px">
        <h2>Пароль панели</h2>
        <form id="passwordForm">
          <label>Текущий пароль<input name="currentPassword" type="password" autocomplete="current-password" required></label>
          <label>Новый пароль<input name="newPassword" type="password" autocomplete="new-password" minlength="8" required></label>
          <button class="primary" type="submit">Сменить пароль</button>
        </form>
        <form id="passwordResetForm" style="margin-top:12px">
          <label>Текущий пароль<input name="currentPassword" type="password" autocomplete="current-password" required></label>
          <button class="danger" type="submit">Сбросить к паролю из KIRO_ADMIN_PASSWORD</button>
        </form>
      </section>
    </div>
  </div>
  <div class="modal" id="modelsModal" role="dialog" aria-modal="true" aria-labelledby="modelsModalTitle">
    <div class="modal-panel models-panel">
      <div class="section-head">
        <h2 id="modelsModalTitle" data-i="models">Модели</h2>
        <button type="button" onclick="closeModelsModal()" data-i="close">Закрыть</button>
      </div>
      <div id="modelsModalAccount" class="muted"></div>
      <div id="modelsModalList" class="models-list"></div>
    </div>
  </div>
<script>
const T={ru:{refresh:'Обновить',dataRefreshOneSecond:'Автообновление: 1 сек',dataRefreshTenSeconds:'Автообновление: 10 сек',dataRefreshOneMinute:'Автообновление: 1 мин',themeLight:'Светлая',themeDark:'Темная',accounts:'Аккаунты',credits:'Credits',requests:'Запросы',settings:'Настройки',creditsRefreshMode:'Обновление credits',refreshAfterRequest:'После каждого запроса',refreshOneMinute:'Раз в 1 минуту',refreshTenMinutes:'Раз в 10 минут',refreshNever:'Никогда',refreshCredits:'Обновить credits',refreshToken:'Обновить токен',sortByName:'По названию',sortByCredits:'По credits',sortByLatency:'По задержке',status:'Статус',name:'Имя',tokenUpdatedAt:'Дата обнов. токена',actions:'Действия',history:'История запросов',time:'Время',account:'Аккаунт',model:'Модель',models:'Модели',inputOutput:'Input / Output',creditsSpent:'Credits потрачено',error:'Ошибка',add:'Добавить',edit:'Изменить',addAccount:'Добавить аккаунт',editAccount:'Изменить аккаунт',close:'Закрыть',latency:'Задержка',saveToken:'Добавить KAS token',updateToken:'Обновить KAS token',kasJson:'KAS JSON из CLI',proxyKey:'Proxy key sk-*',creditsManual:'Credits осталось (если знаешь)',save:'Сохранить',howTo:'Как получить валидный KAS token',check:'Тест',delete:'Удалить',ready:'готов',done:'Готово'},en:{refresh:'Refresh',dataRefreshOneSecond:'Auto-refresh: 1 sec',dataRefreshTenSeconds:'Auto-refresh: 10 sec',dataRefreshOneMinute:'Auto-refresh: 1 min',themeLight:'Light',themeDark:'Dark',accounts:'Accounts',credits:'Credits',requests:'Requests',settings:'Settings',creditsRefreshMode:'Credits refresh',refreshAfterRequest:'After each request',refreshOneMinute:'Every 1 minute',refreshTenMinutes:'Every 10 minutes',refreshNever:'Never',refreshCredits:'Refresh credits',refreshToken:'Refresh token',sortByName:'By name',sortByCredits:'By credits',sortByLatency:'By latency',status:'Status',name:'Name',tokenUpdatedAt:'Token update date',actions:'Actions',history:'Request history',time:'Time',account:'Account',model:'Model',models:'Models',inputOutput:'Input / Output',creditsSpent:'Credits spent',error:'Error',add:'Add',edit:'Edit',addAccount:'Add account',editAccount:'Edit account',close:'Close',latency:'Latency',saveToken:'Add KAS token',updateToken:'Update KAS token',kasJson:'KAS JSON from CLI',proxyKey:'Proxy key sk-*',creditsManual:'Credits remaining (optional)',save:'Save',howTo:'How to get valid KAS token',check:'Test',delete:'Delete',ready:'ready',done:'Ready'},zh:{refresh:'刷新',dataRefreshOneSecond:'自动刷新：1 秒',dataRefreshTenSeconds:'自动刷新：10 秒',dataRefreshOneMinute:'自动刷新：1 分钟',themeLight:'浅色',themeDark:'深色',accounts:'账户',credits:'点数',requests:'请求',settings:'设置',creditsRefreshMode:'点数刷新',refreshAfterRequest:'每次请求后',refreshOneMinute:'每 1 分钟',refreshTenMinutes:'每 10 分钟',refreshNever:'从不',refreshCredits:'刷新点数',refreshToken:'刷新令牌',sortByName:'按名称',sortByCredits:'按点数',sortByLatency:'按延迟',status:'状态',name:'名称',tokenUpdatedAt:'令牌更新日期',actions:'操作',history:'请求',time:'时间',account:'账户',model:'模型',models:'模型',inputOutput:'输入 / 输出',creditsSpent:'消耗点数',error:'错误',add:'添加',edit:'编辑',addAccount:'添加账户',editAccount:'编辑账户',close:'关闭',latency:'延迟',saveToken:'添加 KAS token',updateToken:'更新 KAS token',kasJson:'CLI 的 KAS JSON',proxyKey:'代理密钥 sk-*',creditsManual:'剩余点数（可选）',save:'保存',howTo:'如何获取有效 KAS token',check:'测试',delete:'删除',ready:'就绪',done:'完成'}};
const help={macos:'<h3>macOS</h3><pre>"/Applications/Kiro CLI.app/Contents/MacOS/kiro-cli" login --license free --use-device-flow\nsqlite3 "$HOME/Library/Application Support/kiro-cli/data.sqlite3" "select value from auth_kv where key=\'kirocli:social:token\';" | jq .</pre>',linux:'<h3>Linux</h3><pre>kiro-cli login --license free --use-device-flow\nsqlite3 "$HOME/.config/kiro-cli/data.sqlite3" "select value from auth_kv where key=\'kirocli:social:token\';" | jq .</pre>',windows:'<h3>Windows PowerShell</h3><pre>kiro-cli.exe login --license free --use-device-flow\nsqlite3 "$env:APPDATA\\kiro-cli\\data.sqlite3" "select value from auth_kv where key=\'kirocli:social:token\';" | jq .</pre>'};
let lang=localStorage.getItem('kiro-admin.lang')||'ru'; let theme=localStorage.getItem('kiro-admin.theme')||'light'; let dataRefreshMode=localStorage.getItem('kiro-admin.dataRefreshMode')||'ten_seconds'; let historyRange=localStorage.getItem('kiro-admin.historyRange')||'all'; let historyFrom=localStorage.getItem('kiro-admin.historyFrom')||''; let historyTo=localStorage.getItem('kiro-admin.historyTo')||''; let accountSort=localStorage.getItem('kiro-admin.accountSort')||'name'; let accountSortDir=localStorage.getItem('kiro-admin.accountSortDir')||'asc'; let accountGroupFilter=localStorage.getItem('kiro-admin.accountGroupFilter')||'all'; let osTab='macos'; let settings={groups:[]}; let dataTimer=null; let authPollTimer=null;
const msg=document.getElementById('message'), accountsBody=document.getElementById('accountsBody'), groupsBody=document.getElementById('groupsBody'), historyBody=document.getElementById('historyBody'), accountStatsBody=document.getElementById('accountStatsBody');
function tr(k){return (T[lang]&&T[lang][k])||T.ru[k]||k} function esc(v){return String(v??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[ch]))}
function setMessage(text,failed){msg.textContent=text; msg.style.color=failed?'var(--danger)':'var(--muted)'}
async function api(path,opt){const res=await fetch(path,opt||{}); const data=await res.json().catch(()=>({})); if(!res.ok) throw new Error(data.error||res.statusText); return data}
async function copyAPIKey(key){if(!key){setMessage('Нет sk-ключа',true); return} try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(key)}else{const ta=document.createElement('textarea'); ta.value=key; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.focus(); ta.select(); document.execCommand('copy'); ta.remove()} setMessage('sk-ключ скопирован')}catch(e){setMessage('Не удалось скопировать sk-ключ',true)}}
function applyTheme(){document.documentElement.dataset.theme=theme; document.getElementById('theme').value=theme}
function applyLang(){document.getElementById('lang').value=lang; document.querySelectorAll('[data-i]').forEach(e=>e.textContent=tr(e.dataset.i)); document.getElementById('helpText').innerHTML=help[osTab]; applyTheme(); renderSortControls(); renderDataRefreshMode(); renderHistoryRange(); renderGroupControls();}
function openAccountModal(){clearAuthPolling(); const f=document.getElementById('accountForm'); f.reset(); f.elements.name.readOnly=false; f.elements.rps.value=2; f.elements.concurrency.value=4; document.getElementById('authBox').classList.add('hide'); document.getElementById('authStatus').textContent=''; document.getElementById('authLink').innerHTML=''; renderGroupControls(); f.elements.group.value=accountGroupFilter==='all'?(settings.groups[0]?.name||'default'):accountGroupFilter; document.getElementById('accountModalTitle').textContent=tr('addAccount'); document.querySelector('#accountModal section h2').textContent=tr('saveToken'); document.getElementById('accountModal').classList.add('open'); f.elements.name.focus()}
function openEditAccountModal(name,apiKey,credits,rps,concurrency,group){const f=document.getElementById('accountForm'); f.reset(); f.elements.name.value=name; f.elements.name.readOnly=true; f.elements.apiKey.value=apiKey||''; f.elements.rps.value=rps||2; f.elements.concurrency.value=concurrency||4; renderGroupControls(); f.elements.group.value=group||'default'; if(credits!=null) f.elements.creditsRemaining.value=credits; document.getElementById('accountModalTitle').textContent=tr('editAccount'); document.querySelector('#accountModal section h2').textContent=tr('updateToken'); document.getElementById('accountModal').classList.add('open'); f.elements.kasJson.focus()}
function closeAccountModal(){clearAuthPolling(); document.getElementById('accountModal').classList.remove('open')}
function openSettingsModal(){document.getElementById('settingsModal').classList.add('open')}
function closeSettingsModal(){document.getElementById('settingsModal').classList.remove('open')}
function openModelsModal(name){document.getElementById('modelsModalAccount').textContent=name; document.getElementById('modelsModalList').innerHTML='<div class="muted">loading...</div>'; document.getElementById('modelsModal').classList.add('open')}
function closeModelsModal(){document.getElementById('modelsModal').classList.remove('open')}
function toggleTimeRangeMenu(){document.getElementById('timeRangePicker').classList.toggle('open')}
function closeTimeRangeMenu(){document.getElementById('timeRangePicker').classList.remove('open')}
function historyISO(v){if(!v)return''; const d=new Date(v); return Number.isNaN(d.getTime())?'':d.toISOString()}
function historyURL(){const p=new URLSearchParams({range:historyRange}); const from=historyISO(historyFrom), to=historyISO(historyTo); if(from) p.set('from',from); if(to) p.set('to',to); return '/admin/api/history?'+p.toString()}
async function loadAll(){try{const [acc,hist,st]=await Promise.all([api('/admin/api/accounts'),api(historyURL()),api('/admin/api/settings')]); settings=st; renderSettings(); renderAccounts(acc); renderGroups(st.groups||[]); renderHistory(hist.requests||[]); renderStats(hist.stats||{}); renderUsage(acc); renderHistoryMeta(hist); scheduleDataRefresh(); setMessage(tr('done'))}catch(e){setMessage(e.message,true)}}
async function loadDynamicData(){const [acc,hist]=await Promise.all([api('/admin/api/accounts'),api(historyURL())]); renderAccounts(acc); renderHistory(hist.requests||[]); renderStats(hist.stats||{}); renderUsage(acc); renderHistoryMeta(hist); return acc}
async function loadAccounts(){const acc=await api('/admin/api/accounts'); renderAccounts(acc); renderUsage(acc); return acc}
async function loadModels(name,apiKey){try{openModelsModal(name); setMessage('loading models...'); const headers=apiKey?{'x-api-key':apiKey}:{'X-Kiro-Account':name}; const res=await api('/v1/models',{headers}); const models=(res.data||[]).slice().sort((a,b)=>String(a.id||'').localeCompare(String(b.id||''))); const list=document.getElementById('modelsModalList'); list.innerHTML=models.length?models.map(m=>'<div class="model-row"><code>'+esc(m.id||'-')+'</code><div class="model-meta">'+esc([m.rate_multiplier!=null?m.rate_multiplier+'x credits':'',m.description||''].filter(Boolean).join(' · '))+'</div></div>').join(''):'<div class="muted">-</div>'; setMessage(tr('done'))}catch(e){document.getElementById('modelsModalList').innerHTML='<div class="model-row"><div class="model-meta">'+esc(e.message)+'</div></div>'; setMessage(e.message,true)}}
function renderSettings(){renderGroupControls(); renderGroups(settings.groups||[])}
function renderSortControls(){document.getElementById('accountSort').value=accountSort; document.getElementById('accountSortDir').textContent=accountSortDir==='asc'?'↑':'↓'}
function renderDataRefreshMode(){document.getElementById('dataRefreshMode').value=dataRefreshMode}
function rangeTitle(v){return ({last_5m:'Last 5 minutes',last_15m:'Last 15 minutes',last_1h:'Last 1 hour',last_6h:'Last 6 hours',last_24h:'Last 24 hours',last_7d:'Last 7 days',today:'Сегодня',yesterday:'Вчера',all:'Все даты',custom:'Custom range'})[v]||v}
function renderHistoryRange(){document.querySelectorAll('#timeRangePicker [data-range]').forEach(b=>b.classList.toggle('active',!historyFrom&&!historyTo&&b.dataset.range===historyRange)); document.getElementById('historyFrom').value=historyFrom; document.getElementById('historyTo').value=historyTo; document.getElementById('timeRangeLabel').textContent=(historyFrom||historyTo)?((historyFrom||'...')+' - '+(historyTo||'now')):rangeTitle(historyRange)}
function renderGroupControls(){const groups=settings.groups&&settings.groups.length?settings.groups:[{name:'default'}]; if(accountGroupFilter!=='all'&&!groups.some(g=>g.name===accountGroupFilter)) accountGroupFilter='all'; document.getElementById('accountGroupFilter').innerHTML='<option value="all">Все группы</option>'+groups.map(g=>'<option value="'+esc(g.name)+'">'+esc(g.name)+'</option>').join(''); document.getElementById('accountGroupFilter').value=accountGroupFilter; document.getElementById('accountGroupSelect').innerHTML=groups.map(g=>'<option value="'+esc(g.name)+'">'+esc(g.name)+'</option>').join('')}
function renderHistoryMeta(hist){const reset=hist&&hist.statsResetAt; document.getElementById('statsResetNote').textContent=reset?'Статистика с '+reset:''}
function formatSeconds(v){return v?String(v).replace(/(\.\d+)?(Z|[+-]\d\d:\d\d)$/,'$2'):'-'}
function formatCreditsSpent(v){return v==null?'-':Math.round(Number(v)*10000)/10000}
function numberOrNull(v){return v==null||v===''?null:Number(v)}
function sortValue(a){if(accountSort==='credits') return numberOrNull(a.creditsRemaining); if(accountSort==='latency') return numberOrNull(a.lastTestDurationMs); return String(a.name||'').toLowerCase()}
function compareAccounts(a,b){const av=sortValue(a), bv=sortValue(b); if(av==null&&bv==null) return String(a.name||'').localeCompare(String(b.name||'')); if(av==null) return 1; if(bv==null) return -1; const res=typeof av==='number'&&typeof bv==='number'?av-bv:String(av).localeCompare(String(bv)); return accountSortDir==='asc'?res:-res}
function renderAccounts(data){let accounts=(data.accounts||[]); if(accountGroupFilter!=='all') accounts=accounts.filter(a=>(a.group||'default')===accountGroupFilter); accounts=accounts.slice().sort(compareAccounts); document.getElementById('accountsMetric').textContent=accounts.length; accountsBody.innerHTML=''; for(const a of accounts){const trEl=document.createElement('tr'); const latency=a.lastTestDurationMs!=null?a.lastTestDurationMs+' ms':'-'; const credits=a.creditsRemaining??'?'; const editArgs=[a.name,a.apiKey||'',a.creditsRemaining??null,a.rps||2,a.concurrency||4,a.group||'default'].map(v=>JSON.stringify(v)).join(','); const modelArgs=[a.name,a.apiKey||''].map(v=>JSON.stringify(v)).join(','); const key=a.apiKey||''; const keyArg=JSON.stringify(key); const keyButton=key?'<button class="icon" type="button" title="Копировать sk-ключ" onclick="copyAPIKey('+esc(keyArg)+')">⧉</button>':'<button class="icon" type="button" title="Нет sk-ключа" disabled>⧉</button>'; const enabled=a.enabled!==false; const state=enabled?'включен':'выключен'; const toggleText=enabled?'Выключить аккаунт':'Включить аккаунт'; const statusClass=!enabled?'':(a.status==='ok'?'active':'error'); const statusText=a.statusMessage||state; trEl.innerHTML='<td data-label="name"><div class="account-head"><button class="power-toggle '+(enabled?'on':'off')+'" type="button" title="'+esc(toggleText)+'" aria-label="'+esc(toggleText)+'" onclick="toggleAccount(\''+esc(a.name)+'\')"></button><div><b>'+esc(a.name)+'</b><div class="status '+statusClass+'" title="'+esc(statusText)+'"><span class="dot"></span><span>'+esc(statusText)+'</span></div><div class="muted">'+esc((a.group||'default')+' · '+state+' · '+(a.rps||2)+' rps / '+(a.concurrency||4)+' conc')+'</div></div></div></td><td data-label="sk"><div class="key-inline"><code>'+esc(a.apiKey||a.apiKeyPreview||'-')+'</code>'+keyButton+'</div></td><td data-label="tokenUpdatedAt"><code>'+esc(formatSeconds(a.expiresAt))+'</code></td><td data-label="credits"><div class="inline credit-inline"><span id="credits-'+esc(a.name)+'">'+esc(credits)+'</span><button class="icon" title="'+tr('refreshCredits')+'" onclick="refreshAccountCredits(\''+esc(a.name)+'\')">↻</button></div></td><td data-label="latency" id="latency-'+esc(a.name)+'">'+esc(latency)+'</td><td data-label="actions"><div class="account-actions"><button onclick="loadModels('+esc(modelArgs)+')">'+tr('models')+'</button><button onclick="openEditAccountModal('+esc(editArgs)+')">'+tr('edit')+'</button><button onclick="refreshAccountToken(\''+esc(a.name)+'\')">'+tr('refreshToken')+'</button><button class="primary" onclick="checkAccount(\''+esc(a.name)+'\')">'+tr('check')+'</button><button class="danger" onclick="deleteAccount(\''+esc(a.name)+'\')">'+tr('delete')+'</button></div></td>'; accountsBody.appendChild(trEl)}}
function renderGroups(groups){groupsBody.innerHTML=''; for(const g of groups||[]){const keyArg=JSON.stringify(g.apiKey||''); const trEl=document.createElement('tr'); trEl.innerHTML='<td><b>'+esc(g.name)+'</b></td><td><div class="key-inline"><code>'+esc(g.apiKey||g.apiKeyPreview||'-')+'</code><button class="icon" type="button" title="Копировать sk-ключ группы" onclick="copyAPIKey('+esc(keyArg)+')">⧉</button></div></td><td>'+esc((g.enabled||0)+' / '+(g.accounts||0))+'</td><td>'+esc(g.creditsRemaining==null?'?':Math.round(Number(g.creditsRemaining)*100)/100)+'</td><td><div class="actions"><button onclick="rotateGroupKey(\''+esc(g.name)+'\')">Новый ключ</button><button class="danger" onclick="deleteGroup(\''+esc(g.name)+'\')">Удалить</button></div></td>'; groupsBody.appendChild(trEl)}}
function renderHistory(rows){document.getElementById('requestsMetric').textContent=rows.length; historyBody.innerHTML=''; for(const r of rows){const trEl=document.createElement('tr'); trEl.innerHTML='<td data-label="time">'+esc(r.time||'-')+'</td><td data-label="account">'+esc(r.account||'-')+'</td><td data-label="model">'+esc(r.model||'-')+'</td><td data-label="status">'+esc(r.status||'-')+'</td><td data-label="ms">'+esc(r.durationMs||0)+'</td><td data-label="input/output">'+esc((r.inputTokens||0)+' / '+(r.outputTokens||0))+'</td><td data-label="creditsSpent">'+esc(formatCreditsSpent(r.creditsSpent))+'</td><td data-label="error">'+esc(r.error||'')+'</td>'; historyBody.appendChild(trEl)}}
function renderStats(stats){document.getElementById('successMetric').textContent=stats.success||0; document.getElementById('failedMetric').textContent=stats.failed||0; document.getElementById('totalMetric').textContent=stats.total||0; document.getElementById('statusStats').innerHTML=renderMapStats(stats.statusCounts); document.getElementById('errorStats').innerHTML=renderMapStats(stats.errorCounts); accountStatsBody.innerHTML=''; for(const a of stats.accounts||[]){const trEl=document.createElement('tr'); trEl.innerHTML='<td>'+esc(a.name)+'</td><td>'+esc(a.total)+'</td><td>'+esc(a.success)+'</td><td>'+esc(a.failed)+'</td><td>'+esc(Math.round((a.failureRate||0)*1000)/10)+'%</td><td>'+esc(a.avgDurationMs||0)+'</td><td>'+esc(a.lastError||'')+'</td>'; accountStatsBody.appendChild(trEl)}}
function renderMapStats(items){const rows=Object.entries(items||{}).sort((a,b)=>b[1]-a[1]); return rows.length?rows.map(([k,v])=>'<div class="model-row"><code>'+esc(k)+'</code><div class="model-meta">'+esc(v)+'</div></div>').join(''):'<div class="muted">-</div>'}
function renderUsage(acc){let manual=null; for(const a of acc.accounts||[]){if(a.enabled===false) continue; if(accountGroupFilter!=='all'&&(a.group||'default')!==accountGroupFilter) continue; if(a.creditsRemaining!=null) manual=(manual||0)+Number(a.creditsRemaining)} document.getElementById('creditsMetric').textContent=manual==null?'?':Math.round(manual*100)/100}
async function checkAccount(name){const cell=document.getElementById('latency-'+name); try{setMessage('testing...'); if(cell) cell.textContent='...'; const r=await api('/admin/api/accounts/'+encodeURIComponent(name)+'/check',{method:'POST'}); await loadAccounts(); setMessage(r.ok?'OK '+r.durationMs+'ms':'FAIL '+(r.message||r.status),!r.ok)}catch(e){if(cell) cell.textContent='FAIL'; setMessage(e.message,true)}}
async function refreshAccountToken(name){try{setMessage('refreshing token...'); const a=await api('/admin/api/accounts/'+encodeURIComponent(name)+'/token',{method:'POST'}); if(a.tokenRefreshError){setMessage(a.tokenRefreshError,true); return} await loadAccounts(); setMessage(tr('done'))}catch(e){setMessage(e.message,true)}}
async function refreshAccountCredits(name){const cell=document.getElementById('credits-'+name); try{if(cell) cell.textContent='...'; const a=await api('/admin/api/accounts/'+encodeURIComponent(name)+'/credits',{method:'POST'}); if(a.creditsRefreshError){if(cell) cell.textContent=a.creditsRemaining??'FAIL'; setMessage(a.creditsRefreshError,true); return} if(cell) cell.textContent=a.creditsRemaining??'?'; await loadAccounts(); setMessage(tr('done'))}catch(e){if(cell) cell.textContent='FAIL'; setMessage(e.message,true)}}
async function rotateGroupKey(name){if(!confirm('Создать новый sk-ключ для группы '+name+'?'))return; await api('/admin/api/groups/'+encodeURIComponent(name)+'/key',{method:'POST'}); await loadAll(); setMessage('Ключ группы обновлен')}
async function deleteGroup(name){if(!confirm('Удалить группу '+name+'?'))return; await api('/admin/api/groups/'+encodeURIComponent(name),{method:'DELETE'}); if(accountGroupFilter===name){accountGroupFilter='all'; localStorage.setItem('kiro-admin.accountGroupFilter',accountGroupFilter)} await loadAll(); setMessage('Группа удалена')}
async function changePassword(e){e.preventDefault(); const form=Object.fromEntries(new FormData(e.currentTarget).entries()); try{settings=await api('/admin/api/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(form)}); e.currentTarget.reset(); setMessage('Пароль обновлен')}catch(err){setMessage(err.message,true)}}
async function resetPassword(e){e.preventDefault(); if(!confirm('Сбросить пароль панели к значению из KIRO_ADMIN_PASSWORD?')) return; const form=Object.fromEntries(new FormData(e.currentTarget).entries()); try{settings=await api('/admin/api/password/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(form)}); e.currentTarget.reset(); setMessage('Пароль сброшен')}catch(err){setMessage(err.message,true)}}
function scheduleDataRefresh(){if(dataTimer) clearInterval(dataTimer); const ms=dataRefreshMode==='one_second'?1000:dataRefreshMode==='one_minute'?60000:10000; dataTimer=setInterval(()=>loadDynamicData().catch(e=>setMessage(e.message,true)),ms)}
async function deleteAccount(name){if(!confirm('Delete '+name+'?'))return; await api('/admin/api/accounts/'+encodeURIComponent(name),{method:'DELETE'}); await loadAll()}
async function toggleAccount(name){try{const a=await api('/admin/api/accounts/'+encodeURIComponent(name)+'/toggle',{method:'POST'}); await loadAccounts(); setMessage((a.enabled?'Аккаунт включен: ':'Аккаунт выключен: ')+name)}catch(e){setMessage(e.message,true)}}
async function resetHistory(){if(!confirm('Сбросить историю запросов?'))return; await api('/admin/api/history',{method:'DELETE'}); await loadAll(); setMessage('История сброшена')}
async function resetStats(){if(!confirm('Сбросить статистику? История останется.'))return; const r=await api('/admin/api/stats/reset',{method:'POST'}); await loadAll(); setMessage('Статистика сброшена: '+(r.statsResetAt||''))}
function clearAuthPolling(){if(authPollTimer){clearInterval(authPollTimer); authPollTimer=null}}
async function startAdminAuthorization(){clearAuthPolling(); const box=document.getElementById('authBox'), status=document.getElementById('authStatus'), link=document.getElementById('authLink'); try{box.classList.remove('hide'); status.textContent='Запускаю авторизацию...'; link.innerHTML=''; const started=await api('/admin/api/auth/start',{method:'POST'}); status.textContent='Открой ссылку и подтверди вход. Код: '+started.userCode; const href=started.verificationUriComplete||started.verificationUri; link.innerHTML='<a href="'+esc(href)+'" target="_blank" rel="noopener">Открыть авторизацию</a>'; if(href) window.open(href,'_blank','noopener'); const poll=async()=>{try{const r=await api('/admin/api/auth/'+encodeURIComponent(started.id)); if(r.status==='complete'&&r.kasJson){clearAuthPolling(); document.getElementById('accountForm').elements.kasJson.value=JSON.stringify(r.kasJson,null,2); status.textContent='Авторизация завершена, KAS JSON добавлен в форму'; setMessage('Авторизация завершена'); return} status.textContent='Ожидаю подтверждение входа. Код: '+started.userCode}catch(e){clearAuthPolling(); status.textContent=e.message; setMessage(e.message,true)}}; authPollTimer=setInterval(poll,Math.max(2,Number(started.interval||5))*1000); await poll()}catch(e){box.classList.remove('hide'); status.textContent=e.message; setMessage(e.message,true)}}
document.getElementById('accountForm').addEventListener('submit',async e=>{e.preventDefault(); const form=Object.fromEntries(new FormData(e.currentTarget).entries()); try{const kas=JSON.parse(form.kasJson); const body={name:form.name,accessToken:kas.access_token||kas.accessToken||'',refreshToken:kas.refresh_token||kas.refreshToken||'',profileArn:kas.profile_arn||kas.profileArn||'',expiresAt:kas.expires_at||kas.expiresAt||'',region:kas.region||'',startUrl:kas.start_url||kas.startUrl||'',oauthFlow:kas.oauth_flow||kas.oauthFlow||'',scopes:Array.isArray(kas.scopes)?kas.scopes:[],clientId:kas.client_id||kas.clientId||'',clientSecret:kas.client_secret||kas.clientSecret||'',clientSecretExpiresAt:kas.client_secret_expires_at||kas.clientSecretExpiresAt||'',apiKey:form.apiKey||'',group:form.group||'default',rps:Number(form.rps||2),concurrency:Number(form.concurrency||4)}; if(form.creditsRemaining!=='') body.creditsRemaining=Number(form.creditsRemaining); if(!body.accessToken||!body.refreshToken) throw new Error('KAS JSON must include access_token and refresh_token'); await api('/admin/api/accounts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); closeAccountModal(); e.currentTarget.reset(); await loadAll()}catch(err){setMessage(err.message,true)}});
document.getElementById('groupForm').addEventListener('submit',async e=>{e.preventDefault(); const form=Object.fromEntries(new FormData(e.currentTarget).entries()); try{const result=await api('/admin/api/groups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:form.name})}); if(result.groups){settings.groups=result.groups; renderSettings()} e.currentTarget.reset(); await loadAll(); setMessage('Группа добавлена')}catch(err){setMessage(err.message,true)}});
document.getElementById('lang').addEventListener('change',e=>{lang=e.target.value; localStorage.setItem('kiro-admin.lang',lang); applyLang(); loadAll()}); document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active')); b.classList.add('active'); osTab=b.dataset.os; applyLang()}));
document.getElementById('theme').addEventListener('change',e=>{theme=e.target.value; localStorage.setItem('kiro-admin.theme',theme); applyTheme()});
document.getElementById('dataRefreshMode').addEventListener('change',e=>{dataRefreshMode=e.target.value; localStorage.setItem('kiro-admin.dataRefreshMode',dataRefreshMode); scheduleDataRefresh()});
document.getElementById('timeRangeButton').addEventListener('click',toggleTimeRangeMenu);
document.getElementById('refreshNow').addEventListener('click',()=>loadAll());
document.querySelectorAll('#timeRangePicker [data-range]').forEach(b=>b.addEventListener('click',()=>{historyRange=b.dataset.range; historyFrom=''; historyTo=''; localStorage.setItem('kiro-admin.historyRange',historyRange); localStorage.removeItem('kiro-admin.historyFrom'); localStorage.removeItem('kiro-admin.historyTo'); closeTimeRangeMenu(); renderHistoryRange(); loadAll()}));
document.getElementById('applyHistoryRange').addEventListener('click',()=>{historyFrom=document.getElementById('historyFrom').value; historyTo=document.getElementById('historyTo').value; historyRange=(historyFrom||historyTo)?'custom':historyRange; localStorage.setItem('kiro-admin.historyRange',historyRange); if(historyFrom) localStorage.setItem('kiro-admin.historyFrom',historyFrom); else localStorage.removeItem('kiro-admin.historyFrom'); if(historyTo) localStorage.setItem('kiro-admin.historyTo',historyTo); else localStorage.removeItem('kiro-admin.historyTo'); closeTimeRangeMenu(); renderHistoryRange(); loadAll()});
document.getElementById('accountSort').addEventListener('change',e=>{accountSort=e.target.value; localStorage.setItem('kiro-admin.accountSort',accountSort); loadAccounts().catch(err=>setMessage(err.message,true))});
document.getElementById('accountSortDir').addEventListener('click',()=>{accountSortDir=accountSortDir==='asc'?'desc':'asc'; localStorage.setItem('kiro-admin.accountSortDir',accountSortDir); renderSortControls(); loadAccounts().catch(err=>setMessage(err.message,true))});
document.getElementById('accountGroupFilter').addEventListener('change',e=>{accountGroupFilter=e.target.value; localStorage.setItem('kiro-admin.accountGroupFilter',accountGroupFilter); loadAccounts().catch(err=>setMessage(err.message,true))});
document.querySelectorAll('.view-tab').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.view-tab').forEach(x=>x.classList.remove('active')); document.querySelectorAll('.view-panel').forEach(x=>x.classList.add('hide')); b.classList.add('active'); document.getElementById(b.dataset.view+'View').classList.remove('hide')}));
document.getElementById('passwordForm').addEventListener('submit',changePassword);
document.getElementById('passwordResetForm').addEventListener('submit',resetPassword);
document.getElementById('accountModal').addEventListener('click',e=>{if(e.target.id==='accountModal') closeAccountModal()});
document.getElementById('settingsModal').addEventListener('click',e=>{if(e.target.id==='settingsModal') closeSettingsModal()});
document.getElementById('modelsModal').addEventListener('click',e=>{if(e.target.id==='modelsModal') closeModelsModal()});
document.addEventListener('click',e=>{if(!document.getElementById('timeRangePicker').contains(e.target)) closeTimeRangeMenu()});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeAccountModal(); closeSettingsModal(); closeModelsModal(); closeTimeRangeMenu()}});
applyLang(); loadAll();
</script>
</body>
</html>`

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil // 文件或文件夹存在
	}
	if os.IsNotExist(err) {
		return false, nil // 文件或文件夹不存在
	}
	return false, err // 其他错误
}
