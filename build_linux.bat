@echo off
set GOOS=linux
set GOARCH=amd64
go build -o zns cmd/zns/main.go