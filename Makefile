# LockState — Build system

APP_NAME = lockstate
BUILD_DIR = build
VERSION ?= 0.1.0

.PHONY: all clean windows linux darwin release test

# macOS exclu de `all` : le collecteur Darwin n'existe pas encore (voir la roadmap).
all: windows linux

windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X main.Version=$(VERSION)" \
		-o $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-windows-amd64.exe ./cmd/lockstate/

linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.Version=$(VERSION)" \
		-o $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-amd64 ./cmd/lockstate/

darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w -X main.Version=$(VERSION)" \
		-o $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-darwin-amd64 ./cmd/lockstate/

# Compilation avec stripping symboles (binaire plus petit, plus dur à reverse)
release: all
	strip $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-amd64
	upx --best $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-windows-amd64.exe 2>/dev/null || true
	ls -lh $(BUILD_DIR)/

test:
	go vet ./...
	go test ./...

clean:
	rm -rf $(BUILD_DIR)/
