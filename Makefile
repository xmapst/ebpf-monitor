
IMAGE := ebpf-monitor:latest

.PHONY: build init

build:
	go generate ./...
	go mod tidy
	go vet ./...
	go fmt ./...
	go build -ldflags="-s -w" -trimpath -o bin/ebpf-monitor_linux-amd64 cmd/main.go
	GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o bin/ebpf-monitor_linux-arm64 cmd/main.go
	upx -9 bin/*

init:
	apt-get update
	apt-get install -y llvm clang git curl wget tree libbpf-dev build-essential linux-headers-generic
	ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm