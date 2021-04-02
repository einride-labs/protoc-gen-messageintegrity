SHELL := /bin/bash

.PHONY: all
all: \
	commitlint \
	buf-check-lint \
	buf-generate \
	go-lint \
	go-review \
	go-test \
	go-mod-tidy \
	git-verify-nodiff

include tools/buf/rules.mk
include tools/commitlint/rules.mk
include tools/git-verify-nodiff/rules.mk
include tools/golangci-lint/rules.mk
include tools/goreview/rules.mk
include tools/protoc-gen-go/rules.mk
include tools/protoc/rules.mk
include tools/semantic-release/rules.mk

current_dir = $(shell pwd)

$(protoc_gen_message_integrity):
	$(info [protoc-gen-message-integrity] building binary...)
	@go build -o $(GOPATH)/bin/protoc-gen-messageintegrity cmd/plugin/main.go

.PHONY: clean
clean:
	$(info [$@] removing build files...)
	@rm -rf build

.PHONY: go-test
go-test:
	$(info [$@] running Go tests...)
	@mkdir -p build/coverage
	@go test -short -race -coverprofile=build/coverage/$@.txt -covermode=atomic ./...

.PHONY: go-integration-test
go-integration-test:
	$(info [$@] running Go tests (including integration tests)...)
	@mkdir -p build/coverage
	@go test -race -cover -coverprofile=build/coverage/$@.txt -covermode=atomic ./...

.PHONY: go-mod-tidy
go-mod-tidy:
	$(info [$@] tidying Go module files...)
	@go mod tidy -v

.PHONY: buf-check-lint
buf-check-lint: $(buf)
	$(info [$@] linting protobuf schemas...)
	@$(buf) check lint

build-plugin:
	$(info [$@] building the plugin...)
	@go build -o $(GOPATH)/bin/protoc-gen-messageintegrity cmd/plugin/main.go

.PHONY: buf-generate
buf-generate: $(buf) $(protoc) $(protoc_gen_go) $(protoc_gen_message_integrity) build-plugin
	$(info [$@] generating protobuf stubs...)
	@rm -rf proto/gen
	@$(buf) generate

build: build-plugin
	$(info [$@] building the example main...)
	@go build -o bin/main cmd/example/main.go

run:
	$(info [$@] running the example main...)
	@go run cmd/example/main.go

benchmark:
	$(info [$@] running Message Integrity Plugin benchmark...)
	@go test -bench=. ./cmd/example
