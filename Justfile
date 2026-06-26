# Justfile for mcp-os-agent

# Build all binaries
build:
    go build -o bin/agent cmd/agent/main.go
    go build -o bin/gateway cmd/gateway/main.go
    go build -o bin/myrmex cmd/myrmex/main.go

# Run syntax check and linting
validate:
    go vet ./...
    go fmt ./...

# Run tests
test:
    go test -v ./...

# Generate SSH keys for local testing
generate-keys:
    bash generate_keys.sh

# Run gateway locally
run-gateway: build
    ./bin/gateway -config gateway_config.json

# Run agent locally
run-agent: build
    ./bin/agent -config agent_config.json

# Clean up binaries and keys
clean:
    rm -rf bin/ id_ed25519 id_ed25519.pub authorized_keys test_env

# Run automated Docker Compose integration tests
docker-test:
    ./setup_test_env.sh
    go run cmd/integration-test/main.go
