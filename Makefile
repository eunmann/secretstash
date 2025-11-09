.PHONY: help build run test clean docker-build docker-run docker-stop fmt lint

# Variables
BINARY_NAME=secrets-manager-local
DOCKER_IMAGE=aws-secrets-manager-local
DOCKER_TAG=latest
PORT?=18080

help: ## Display this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

build: ## Build the application binary
	@echo "Building $(BINARY_NAME)..."
	go build -o bin/$(BINARY_NAME) ./cmd/server

run: ## Run the application locally
	@echo "Running $(BINARY_NAME) on port $(PORT)..."
	PORT=$(PORT) go run ./cmd/server/main.go

test: ## Run unit tests
	@echo "Running tests..."
	go test -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests and show coverage
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

fmt: ## Format Go code
	@echo "Formatting code..."
	go fmt ./...

lint: ## Run linter using golangci-lint
	@echo "Running linter..."
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run ./...

lint-fix: ## Run linter and auto-fix issues
	@echo "Running linter with auto-fix..."
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --fix ./...

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

mod-tidy: ## Tidy go modules
	@echo "Tidying go modules..."
	go mod tidy

mod-download: ## Download go modules
	@echo "Downloading go modules..."
	go mod download

##@ Docker

docker-build: ## Build Docker image
	@echo "Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run: ## Run Docker container
	@echo "Running Docker container on port $(PORT)..."
	docker run -d --name $(BINARY_NAME) -p $(PORT):18080 $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-run-persistent: ## Run Docker container with persistence
	@echo "Running Docker container with persistence..."
	docker run -d --name $(BINARY_NAME) \
		-p $(PORT):18080 \
		-v $(PWD)/data:/data \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

docker-stop: ## Stop and remove Docker container
	@echo "Stopping Docker container..."
	docker stop $(BINARY_NAME) || true
	docker rm $(BINARY_NAME) || true

docker-logs: ## Show Docker container logs
	docker logs -f $(BINARY_NAME)

docker-compose-up: ## Start services with docker-compose
	@echo "Starting services with docker-compose..."
	docker-compose up -d

docker-compose-down: ## Stop services with docker-compose
	@echo "Stopping services with docker-compose..."
	docker-compose down

docker-compose-logs: ## Show docker-compose logs
	docker-compose logs -f

##@ Cleanup

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -rf data/

clean-all: clean docker-stop ## Clean everything including Docker artifacts
	@echo "Removing Docker image..."
	docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) || true
	docker-compose down -v || true

##@ Integration

test-integration: docker-compose-up ## Run integration tests (requires docker-compose)
	@echo "Waiting for service to be ready..."
	@sleep 3
	@echo "Running integration tests..."
	@curl -f http://localhost:$(PORT)/health || (echo "Health check failed" && exit 1)
	@echo "Service is healthy!"
	$(MAKE) docker-compose-down

example-create-secret: ## Example: Create a secret
	@echo "Creating example secret..."
	@curl -X POST http://localhost:$(PORT)/ \
		-H "X-Amz-Target: secretsmanager.CreateSecret" \
		-H "Content-Type: application/x-amz-json-1.1" \
		-d '{"Name":"example-secret","SecretString":"my-secret-value"}' | jq

example-get-secret: ## Example: Get a secret
	@echo "Getting example secret..."
	@curl -X POST http://localhost:$(PORT)/ \
		-H "X-Amz-Target: secretsmanager.GetSecretValue" \
		-H "Content-Type: application/x-amz-json-1.1" \
		-d '{"SecretId":"example-secret"}' | jq

example-list-secrets: ## Example: List all secrets
	@echo "Listing secrets..."
	@curl -X POST http://localhost:$(PORT)/ \
		-H "X-Amz-Target: secretsmanager.ListSecrets" \
		-H "Content-Type: application/x-amz-json-1.1" \
		-d '{}' | jq

##@ Default

.DEFAULT_GOAL := help
