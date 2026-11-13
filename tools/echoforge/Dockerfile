FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git for go module downloads
RUN apk add --no-cache git ca-certificates tzdata

# Copy go module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=1.0.0 -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo 'docker')" \
    -o /bin/echoforge \
    ./cmd/echoforge/

# ── Final stage: minimal image ────────────────────────────────────────────────
FROM alpine:3.19

# Import certificates and timezone data
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /bin/echoforge /usr/local/bin/echoforge

# Copy data directory (wordlists, patterns)
COPY --from=builder /app/data /data

WORKDIR /workspace

# Create output directory
RUN mkdir -p /workspace/output

ENTRYPOINT ["echoforge"]
CMD ["--help"]

# Usage:
# docker build -t echoforge .
# docker run --rm -v $(pwd)/output:/workspace/output echoforge -d example.com --output all
