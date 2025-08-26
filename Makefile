.PHONY: build install test release

build:
	go build -o bin/domwatch ./cmd/domwatch

install:
	go install ./cmd/domwatch

test:
	go test ./...

release:
	goreleaser release --clean
