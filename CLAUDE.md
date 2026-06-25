# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go CLI tool called `kiro2cc` that manages Kiro authentication tokens and provides Anthropic and OpenAI-compatible API proxy endpoints. The tool acts as a bridge between Anthropic/OpenAI-style requests and AWS CodeWhisperer, translating requests and responses between the formats.

## Build and Development Commands

```bash
# Build the application
go build -o kiro2cc main.go

# Run tests
go test ./...

# Run specific test in parser package
go test ./parser -v

# Run the application
./kiro2cc [command]
```

## Application Commands

- `./kiro2cc read` - Read and display token information
- `./kiro2cc refresh` - Refresh the access token using refresh token
- `./kiro2cc export` - Export environment variables for other tools
- `./kiro2cc server [port]` - Start HTTP proxy server (default port 8080)

## Architecture

### Core Components

1. **Token Management** (`main.go:337-486`)
   - Reads tokens from `~/.aws/sso/cache/kiro-auth-token.json`
   - Handles token refresh via Kiro auth service
   - Cross-platform environment variable export

2. **API Translation** (`main.go:232-303`)
   - Converts Anthropic API requests to CodeWhisperer format
   - Maps model names via `ModelMap` (line 218-221)
   - Handles conversation history and system messages

3. **HTTP Proxy Server** (`main.go:514-893`)
   - Serves on `/v1/messages` and `/v1/chat/completions` endpoints
   - Supports both streaming and non-streaming requests
   - Automatic token refresh on 403 errors

4. **Response Parser** (`parser/sse_parser.go`)
   - Parses binary CodeWhisperer responses
   - Converts to Anthropic-compatible SSE events
   - Handles tool use and text content blocks

### Key Data Structures

- `AnthropicRequest` - Internal Anthropic-compatible request format
- `OpenAIChatCompletionRequest` - Incoming OpenAI-compatible chat requests
- `CodeWhispererRequest` - Outgoing AWS requests  
- `TokenData` - Authentication token storage
- `SSEEvent` - Streaming response events

### Request Flow

1. Client sends Anthropic API request to `/v1/messages` or OpenAI Chat Completions request to `/v1/chat/completions`
2. Server reads token from filesystem
3. OpenAI requests are converted to Anthropic format, then requests are converted to CodeWhisperer format
4. Proxied to AWS CodeWhisperer API
5. Response parsed and converted back to Anthropic or OpenAI-compatible format
6. Streamed or returned as JSON to client

## Development Notes

- Uses hardcoded proxy `127.0.0.1:9000` for AWS requests
- Model mapping required between Anthropic and CodeWhisperer model IDs
- Response files saved as `msg_[timestamp]response.raw` for debugging
- Automatic token refresh on authentication failures
