FROM golang:1.25.6-alpine AS builder

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kiro-admin main.go

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
	&& mkdir -p /root/.aws/sso \
	&& ln -s /tokens /root/.aws/sso/cache

ENV KIRO_ADMIN_TOKEN_DIR=/tokens
WORKDIR /app

COPY --from=builder /out/kiro-admin /usr/local/bin/kiro-admin

EXPOSE 8080

ENTRYPOINT ["kiro-admin"]
CMD ["server", "8080"]
