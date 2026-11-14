# -----------------------------------------------------------------------------
# Stage 1: Build & Test Native Go REST & WebSocket API Server
# -----------------------------------------------------------------------------
FROM golang:1.26-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

WORKDIR /src

ARG VERSION=dev

COPY go.mod ./
COPY main.go keystore_test.go admin.html admin.js docs.html docs.js test.html test.js openapi.json ./

RUN CGO_ENABLED=0 go test -v ./... && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.appVersion=${VERSION}" -o /bin/signal-api main.go

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
    chown -R 10001:10001 /app /home/.local/share/signal-cli && \
    SQLITE_JAR=$(find /usr -name 'sqlite-jdbc-*.jar' | head -n1) && \
    unzip -p "$SQLITE_JAR" "org/sqlite/native/Linux-Musl/$(uname -m)/libsqlitejdbc.so" > /usr/lib/libsqlitejdbc.so && \
    test -s /usr/lib/libsqlitejdbc.so && \
    chmod 755 /usr/lib/libsqlitejdbc.so

WORKDIR /app

# Copy compiled Go static binary and documentation/UI assets
COPY --from=builder --chown=10001:10001 /bin/signal-api /app/signal-api
COPY --chown=10001:10001 openapi.json /app/openapi.json
COPY --chown=10001:10001 docs.html /app/docs.html
COPY --chown=10001:10001 docs.js /app/docs.js
COPY --chown=10001:10001 admin.html /app/admin.html
COPY --chown=10001:10001 admin.js /app/admin.js
COPY --chown=10001:10001 test.html /app/test.html
COPY --chown=10001:10001 test.js /app/test.js

ARG VERSION=dev
ENV PORT=8080 \
    HOME=/home/.local/share/signal-cli \
    XDG_DATA_HOME=/home/.local/share \
    SIGNAL_CLI_OPTS="-Dorg.sqlite.lib.path=/usr/lib" \
    APP_VERSION=${VERSION}

RUN printf '#!/bin/sh\nexec /app/signal-api register-recovery "$@"\n' > /usr/local/bin/register-recovery && \
    chmod 755 /usr/local/bin/register-recovery

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/signal-api", "healthcheck"]

ENTRYPOINT ["/app/signal-api"]

LABEL org.opencontainers.image.source="https://github.com/timcappalli/signal-cli-api"
LABEL org.opencontainers.image.version="1.2.1"