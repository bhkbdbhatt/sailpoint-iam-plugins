# Sentinel — developer tasks
#
# Requires: Go 1.27+, and optionally golangci-lint, govulncheck, gosec,
# goreleaser. Run `make help` to list targets.

BINARY   := sentinel
PKG      := github.com/sentinel-iam/sentinel
CMD      := ./cmd/sentinel
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
LDFLAGS  := -s -w \
	-X $(PKG)/internal/cli.version=$(VERSION) \
	-X $(PKG)/internal/cli.commit=$(COMMIT) \
	-X $(PKG)/internal/cli.date=$(DATE)

GOBIN    := $(shell go env GOPATH)/bin

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary into ./bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(CMD)

.PHONY: install
install: ## Install the binary into GOBIN
	go install -trimpath -ldflags "$(LDFLAGS)" $(CMD)

.PHONY: run
run: ## Run the API server (serve)
	go run $(CMD) serve

.PHONY: test
test: ## Run unit tests
	go test ./...

.PHONY: test-race
test-race: ## Run unit tests with the race detector
	go test -race ./...

.PHONY: cover
cover: ## Run tests and write coverage.out; prints the total
	go test -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

.PHONY: cover-html
cover-html: cover ## Open the HTML coverage report
	go tool cover -html=coverage.out

.PHONY: fmt
fmt: ## Format the code
	gofmt -w . && go mod tidy

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: vuln
vuln: ## Run govulncheck
	govulncheck ./...

.PHONY: sec
sec: ## Run gosec
	gosec -quiet ./...

.PHONY: check
check: vet lint test-race ## Run vet, lint and race tests

.PHONY: tidy
tidy: ## Tidy go.mod/go.sum
	go mod tidy

.PHONY: release-dry
release-dry: ## Build a full local release snapshot with goreleaser
	goreleaser release --snapshot --clean

.PHONY: docker
docker: ## Build the container image
	docker build -t sentinel:$(VERSION) .

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -rf bin dist coverage.out
