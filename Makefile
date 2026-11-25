VERSION ?= dev
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
IMAGE ?= subregator-backend:local
LDFLAGS = -s -w -X main.version=$(VERSION) -X main.revision=$(REVISION)

.PHONY: check fmt fmt-check test vet build run image smoke up down load-test
check: fmt-check vet test
fmt:
	gofmt -w cmd internal
fmt-check:
	@test -z "$$(gofmt -l cmd internal)"
test:
	@test -n "$$TEST_DATABASE_URL" || (echo "Set TEST_DATABASE_URL for PostgreSQL integration tests" >&2; exit 1)
	go test -race ./...
vet:
	go vet ./...
build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o bin/subregator ./cmd/subregator
run:
	go run ./cmd/subregator
image:
	docker build --build-arg VERSION="$(VERSION)" --build-arg REVISION="$(REVISION)" -t "$(IMAGE)" .
smoke:
	./scripts/smoke-container.sh "$(IMAGE)"
up:
	docker compose up -d --build
down:
	docker compose down

load-test:
	SUBREGATOR_LOADTEST=1 SUBREGATOR_LOAD_LIMITS=1 go test ./internal/api -run '^TestLocalLoad$$' -v -count=1 -timeout=5m
