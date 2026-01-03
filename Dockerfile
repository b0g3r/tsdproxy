# Build web assets
FROM oven/bun:1 AS web-builder
WORKDIR /app/web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN bun run build

# Build Go application
FROM golang:1.24 AS builder
RUN apk add --no-cache ca-certificates && update-ca-certificates 2>/dev/null || true

WORKDIR /app

# Install templ for template generation
RUN go install github.com/a-h/templ/cmd/templ@latest

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Copy built web assets from web-builder
COPY --from=web-builder /app/web/dist ./web/dist

# Generate templ files
RUN templ generate

# Build Go binaries
RUN CGO_ENABLED=0 GOOS=linux go build -o /tsdproxyd ./cmd/server/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /healthcheck ./cmd/healthcheck/main.go

# Final stage
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /tsdproxyd /tsdproxyd
COPY --from=builder /healthcheck /healthcheck

ENTRYPOINT ["/tsdproxyd"]

EXPOSE 8080
HEALTHCHECK CMD [ "/healthcheck" ]
