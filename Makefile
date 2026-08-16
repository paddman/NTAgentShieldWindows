VERSION ?= $(shell cat VERSION)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILDINFO_PKG := github.com/paddman/NTAgentShieldWindows/internal/buildinfo
LDFLAGS := -s -w -X $(BUILDINFO_PKG).Version=$(VERSION) -X $(BUILDINFO_PKG).Commit=$(COMMIT) -X $(BUILDINFO_PKG).Date=$(DATE)

.PHONY: fmt test vet build cross demo clean

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

test:
	go test ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ntagentshield-agent ./cmd/ntagentshield-agent
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ntagentshieldctl ./cmd/ntagentshieldctl
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ntagentshield-sensor ./cmd/ntagentshield-sensor
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ntagentshield-response ./cmd/ntagentshield-response
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ntagentshield-doctor ./cmd/ntagentshield-doctor

cross:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ntagentshield-agent-linux-amd64 ./cmd/ntagentshield-agent
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ntagentshield-agent-windows-amd64.exe ./cmd/ntagentshield-agent
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ntagentshieldctl-linux-amd64 ./cmd/ntagentshieldctl
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ntagentshield-sensor-linux-amd64 ./cmd/ntagentshield-sensor
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ntagentshield-response-linux-amd64 ./cmd/ntagentshield-response
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ntagentshield-doctor-linux-amd64 ./cmd/ntagentshield-doctor
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ntagentshieldctl-windows-amd64.exe ./cmd/ntagentshieldctl

demo:
	go run ./cmd/ntagentshieldctl scan-log --format iis_w3c --file examples/logs/iis.log

clean:
	rm -rf bin dist coverage.out coverage.html
