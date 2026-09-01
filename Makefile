VERSION ?= 0.2.2
GO ?= go
PLUGIN_ID = agy-identity-bridge
OUT = dist/agy-identity-bridge-v$(VERSION).so
ARCHIVE = dist/$(PLUGIN_ID)_$(VERSION)_linux_amd64.zip

.PHONY: build test clean

build:
	test "$$(go env GOOS)" = "linux"
	test "$$(go env GOARCH)" = "amd64"
	mkdir -p dist
	CGO_ENABLED=1 $(GO) build -buildvcs=false -trimpath -buildmode=c-shared \
		-ldflags "-s -w -X main.pluginVersion=$(VERSION)" -o "$(OUT)" ./src
	rm -f dist/*.h

test:
	$(GO) vet ./...
	$(GO) test ./...

clean:
	rm -rf dist
