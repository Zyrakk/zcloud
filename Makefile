.PHONY: all build build-client build-server clean install-client install-server test deps dev-server dev-client check-go

VERSION ?= $(shell if [ -f VERSION ]; then cat VERSION; else git describe --tags --abbrev=0 2>/dev/null || echo dev; fi)
GO ?= go
GO_MIN_VERSION ?= 1.22

UNAME_M := $(shell uname -m)
INSTALL_ARCH := $(if $(filter x86_64,$(UNAME_M)),amd64,$(if $(filter aarch64,$(UNAME_M)),arm64,amd64))
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

all: build

build: build-client build-server

check-go:
	@if ! command -v "$(GO)" >/dev/null 2>&1; then \
		echo "Error: Go $(GO_MIN_VERSION)+ is required but was not found in PATH." >&2; \
		echo "Install Go from https://go.dev/doc/install, then run 'make build-client' again." >&2; \
		exit 127; \
	fi
	@actual=$$($(GO) version | awk '{print $$3}' | sed 's/^go//'); \
	minimum="$(GO_MIN_VERSION)"; \
	if [ "$$(printf '%s\n' "$$minimum" "$$actual" | sort -V | head -n1)" != "$$minimum" ]; then \
		echo "Error: Go $$minimum+ is required (found $$actual)." >&2; \
		exit 1; \
	fi

build-client: check-go
	@echo "Building zcloud client..."
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/zcloud-linux-amd64 ./cmd/zcloud
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/zcloud-linux-arm64 ./cmd/zcloud
	@echo "Done: dist/zcloud-linux-{amd64,arm64}"

build-server: check-go
	@echo "Building zcloud-server..."
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/zcloud-server-linux-amd64 ./cmd/zcloud-server
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/zcloud-server-linux-arm64 ./cmd/zcloud-server
	@echo "Done: dist/zcloud-server-linux-{amd64,arm64}"

clean:
	rm -rf dist/

install-client: build-client
	@echo "Installing zcloud client..."
	sudo cp dist/zcloud-linux-$(INSTALL_ARCH) /usr/local/bin/zcloud
	sudo chmod +x /usr/local/bin/zcloud
	@echo "Installed: /usr/local/bin/zcloud"

install-server: build-server
	@echo "Installing zcloud-server..."
	sudo mkdir -p /opt/zcloud-server
	sudo cp dist/zcloud-server-linux-$(INSTALL_ARCH) /opt/zcloud-server/zcloud-server
	sudo chmod +x /opt/zcloud-server/zcloud-server
	sudo cp configs/zcloud-server.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Installed: /opt/zcloud-server/zcloud-server"
	@echo "Run 'sudo /opt/zcloud-server/zcloud-server --init' to initialize"

test:
	$(MAKE) check-go
	$(GO) test -v ./...

deps:
	$(MAKE) check-go
	$(GO) mod download
	$(GO) mod tidy

# Development targets
dev-server:
	$(MAKE) check-go
	$(GO) run ./cmd/zcloud-server --config configs/dev-config.yaml

dev-client:
	$(MAKE) check-go
	$(GO) run ./cmd/zcloud
