.PHONY: all build build-client build-server clean install-client install-server test

VERSION := 1.4.4
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

all: build

build: build-client build-server

build-client:
	@echo "Building zcloud client..."
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/zcloud-linux-amd64 ./cmd/zcloud
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/zcloud-linux-arm64 ./cmd/zcloud
	@echo "Done: dist/zcloud-linux-{amd64,arm64}"

build-server:
	@echo "Building zcloud-server..."
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/zcloud-server-linux-amd64 ./cmd/zcloud-server
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/zcloud-server-linux-arm64 ./cmd/zcloud-server
	@echo "Done: dist/zcloud-server-linux-{amd64,arm64}"

clean:
	rm -rf dist/

install-client: build-client
	@echo "Installing zcloud client..."
	sudo cp dist/zcloud-linux-amd64 /usr/local/bin/zcloud
	sudo chmod +x /usr/local/bin/zcloud
	@echo "Installed: /usr/local/bin/zcloud"

install-server: build-server
	@echo "Installing zcloud-server..."
	sudo mkdir -p /opt/zcloud-server
	sudo cp dist/zcloud-server-linux-amd64 /opt/zcloud-server/zcloud-server
	sudo chmod +x /opt/zcloud-server/zcloud-server
	sudo cp configs/zcloud-server.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Installed: /opt/zcloud-server/zcloud-server"
	@echo "Run 'sudo /opt/zcloud-server/zcloud-server --init' to initialize"

test:
	go test -v ./...

deps:
	go mod download
	go mod tidy

# Development targets
dev-server:
	go run ./cmd/zcloud-server --config configs/dev-config.yaml

dev-client:
	go run ./cmd/zcloud
