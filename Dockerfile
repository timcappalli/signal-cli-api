# -----------------------------------------------------------------------------
# Stage 1: Build & Test Native Go REST & WebSocket API Server
# -----------------------------------------------------------------------------
FROM golang:1.26-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

WORKDIR /src

COPY go.mod ./
COPY main.go keystore_test.go admin.html admin.js docs.html docs.js openapi.json ./

RUN CGO_ENABLED=0 go test -v ./... && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/signal-api main.go

# -----------------------------------------------------------------------------
# Stage 2: Hardened Alpine 3.24 Runtime with native signal-cli (non-root, no shell/curl)
# -----------------------------------------------------------------------------
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# Install only native signal-cli, ca-certificates, and tzdata (no bash or curl)
RUN apk add --no-cache \
    signal-cli \
    ca-certificates \
    tzdata && \
    addgroup -g 10001 -S signalapi && \
    adduser -u 10001 -S -G signalapi -h /home/.local/share/signal-cli -s /sbin/nologin signalapi && \
    mkdir -p /app /home/.local/share/signal-cli && \
    chmod 700 /home/.local/share/signal-cli && \
    chown -R 10001:10001 /app /home/.local/share/signal-cli

WORKDIR /app

# Copy compiled Go static binary and documentation/UI assets
COPY --from=builder --chown=10001:10001 /bin/signal-api /app/signal-api
COPY --chown=10001:10001 openapi.json /app/openapi.json
COPY --chown=10001:10001 docs.html /app/docs.html
COPY --chown=10001:10001 docs.js /app/docs.js
COPY --chown=10001:10001 admin.html /app/admin.html
COPY --chown=10001:10001 admin.js /app/admin.js

ENV PORT=8080 \
    HOME=/home/.local/share/signal-cli

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/signal-api", "healthcheck"]

ENTRYPOINT ["/app/signal-api"]

LABEL org.opencontainers.image.source="https://github.com/timcappalli/signal-cli-api"