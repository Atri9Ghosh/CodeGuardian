# CodeGuardian Makefile

.PHONY: help build test run clean docker-build docker-run lint fmt deps

# Default target
help:
	@echo "CodeGuardian - Security-focused AI DevOps tool"
	@echo ""
	@echo "Available commands:"
	@echo "  build        - Build the application"
	@echo "  test         - Run tests"
	@echo "  run          - Run the application locally"
	@echo "  clean        - Clean build artifacts"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker Compose"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  deps         - Download dependencies"
	@echo "  install      - Install dependencies and build"

# Build the application
build:
	@echo "Building CodeGuardian..."
	go build -o bin/codeguardian ./cmd/codeguardian

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run the application locally
run:
	@echo "Running CodeGuardian..."
	go run ./cmd/codeguardian

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	go clean

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t codeguardian:latest .

# Run with Docker Compose
docker-run:
	@echo "Starting CodeGuardian with Docker Compose..."
	docker-compose up -d

# Run with Docker Compose (with monitoring)
docker-run-monitoring:
	@echo "Starting CodeGuardian with monitoring..."
	docker-compose --profile monitoring up -d

# Stop Docker Compose
docker-stop:
	@echo "Stopping CodeGuardian..."
	docker-compose down

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Install dependencies and build
install: deps build

# Run security tests
test-security:
	@echo "Running security tests..."
	go test -v ./tests/security

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	go test -v ./tests/integration

# Generate mocks (if using mockery)
mocks:
	@echo "Generating mocks..."
	mockery --all

# Check for vulnerabilities in dependencies
check-deps:
	@echo "Checking for vulnerabilities in dependencies..."
	govulncheck ./...

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench=. ./...

# Show test coverage
coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Development setup
dev-setup: deps build
	@echo "Development setup complete!"
	@echo "Next steps:"
	@echo "1. Copy env.example to .env and configure your settings"
	@echo "2. Run 'make run' to start the application"
	@echo "3. Or run 'make docker-run' to start with Docker"

# Production build
prod-build:
	@echo "Building for production..."
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/codeguardian ./cmd/codeguardian

# Create release
release:
	@echo "Creating release..."
	@read -p "Enter version (e.g., v1.0.0): " version; \
	git tag $$version; \
	git push origin $$version; \
	echo "Release $$version created!"

# Show application info
info:
	@echo "CodeGuardian Application Info:"
	@echo "Version: 1.0.0"
	@echo "Go version: $(shell go version)"
	@echo "Git commit: $(shell git rev-parse --short HEAD)"
	@echo "Build time: $(shell date)"
