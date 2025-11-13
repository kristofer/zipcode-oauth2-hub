# ZipCode OAuth2 Hub Makefile

.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make setup          - Initial setup (install dependencies, copy env file)"
	@echo "  make docker-up      - Start Docker services (Keycloak, PostgreSQL, Redis)"
	@echo "  make docker-down    - Stop Docker services"
	@echo "  make run-gateway    - Run the API Gateway"
	@echo "  make run-example    - Run the example productivity app"
	@echo "  make test           - Run all tests"
	@echo "  make test-coverage  - Run tests with coverage"
	@echo "  make lint           - Run golangci-lint"
	@echo "  make build          - Build all binaries"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make keycloak-export - Export current Keycloak realm configuration"

.PHONY: setup
setup:
	@echo "Setting up ZipCode OAuth2 Hub..."
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env file"; fi
	@go mod download
	@echo "Setup complete! Edit .env file if needed, then run 'make docker-up'"

.PHONY: docker-up
docker-up:
	@echo "Starting Docker services..."
	@cd config/docker && docker-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo "Services started! Keycloak: http://localhost:8080"

.PHONY: docker-down
docker-down:
	@echo "Stopping Docker services..."
	@cd config/docker && docker-compose down

.PHONY: docker-logs
docker-logs:
	@cd config/docker && docker-compose logs -f

.PHONY: run-gateway
run-gateway:
	@echo "Starting API Gateway..."
	@go run cmd/gateway/main.go

.PHONY: run-example
run-example:
	@echo "Starting example productivity app..."
	@cd examples/productivity-app1 && go run main.go

.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: lint
lint:
	@echo "Running linter..."
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@golangci-lint run

.PHONY: build
build:
	@echo "Building binaries..."
	@mkdir -p bin
	@echo "Building gateway..."
	@go build -o bin/gateway cmd/gateway/main.go
	@echo "Building example app..."
	@go build -o bin/productivity-app examples/productivity-app1/main.go
	@echo "Build complete! Binaries in ./bin/"

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@go clean -cache

.PHONY: keycloak-export
keycloak-export:
	@echo "Exporting Keycloak realm configuration..."
	@docker exec -it zipcode-keycloak \
		/opt/keycloak/bin/kc.sh export \
		--dir /tmp \
		--realm zipcodewilmington
	@docker cp zipcode-keycloak:/tmp/zipcodewilmington-realm.json \
		config/keycloak/realm-export-backup.json
	@echo "Realm exported to config/keycloak/realm-export-backup.json"

.PHONY: dev
dev:
	@echo "Starting development environment..."
	@make docker-up
	@echo "Waiting for services..."
	@sleep 15
	@make -j2 run-gateway run-example
