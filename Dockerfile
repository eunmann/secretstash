# Multi-stage Dockerfile for SecretStash - Local AWS Secrets Manager Mock

# Stage 1: Build
FROM golang:1.25-alpine AS builder

# Accept build arguments for multi-platform support
ARG TARGETOS
ARG TARGETARCH

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with multi-platform support
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /app/server \
    ./cmd/server

# Stage 2: Runtime
FROM alpine:3.19

# Install wget for healthcheck
RUN apk --no-cache add wget

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

# Create data directory for persistence
RUN mkdir -p /data && chown appuser:appuser /data

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/server .

# Change ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 18080

# Set default environment variables
ENV PORT=18080
ENV PERSISTENCE_FILE=/data/secrets.json

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 -O /dev/null http://localhost:18080/health || exit 1

# Run the application
CMD ["./server"]
