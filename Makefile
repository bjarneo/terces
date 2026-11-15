VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BIN     := bin/terces
TEST_DB := postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable

.PHONY: build test test-db db-up db-down vet rules site clean

## build: build the binary into bin/. Rebuild after a change to rules/*.yaml.
build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/terces

## test: run the tests that do not need Postgres.
test:
	go test ./...

## test-db: run all tests, including the Postgres tests. Run `make db-up` first.
test-db:
	TERCES_TEST_DATABASE_URL='$(TEST_DB)' go test -race -count=1 ./...

## db-up: start a temporary Postgres container for tests.
db-up:
	docker run -d --rm --name terces-test-pg -e POSTGRES_PASSWORD=test \
		-p 127.0.0.1:55432:5432 postgres:17-alpine

## db-down: stop the test container.
db-down:
	docker stop terces-test-pg

vet:
	go vet ./...

## rules: convert a gitleaks config. Example: make rules GITLEAKS_TOML=gitleaks.toml
rules:
	@test -n "$(GITLEAKS_TOML)" || { echo "set GITLEAKS_TOML to the path of gitleaks.toml"; exit 2; }
	go run ./cmd/terces rules import-gitleaks $(GITLEAKS_TOML) \
		--exclude aws-access-token,private-key -o rules/gitleaks.yaml

## site: rebuild the examples of the GitHub Pages site from a synthetic repository.
site: build
	scripts/site-examples.sh

clean:
	rm -rf bin
