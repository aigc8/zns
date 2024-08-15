@echo off
set GOOS=linux
set GOARCH=amd64
go build -o zns_linux_amd64 cmd/zns/main.go