.PHONY: run build test build-arm64 clean

run:
	go run ./cmd/auth

build:
	mkdir -p bin
	go build -o bin/auth ./cmd/auth

test:
	go test -v ./...

build-arm64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/auth-linux-arm64 ./cmd/auth

clean:
	rm -rf bin/ data/
