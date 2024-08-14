@echo off
echo 正在更新依赖...
go mod tidy
if %errorlevel% neq 0 (
    echo 更新依赖失败，请检查错误信息。
    pause
    exit /b 1
)

echo 正在编译 ZNS 项目为 Linux AMD64 版本...
set CGO_ENABLED=0
go env -w GOOS=linux GOARCH=amd64
go build -ldflags="-s -w" -o zns_linux_amd64_static ./cmd/zns
if %errorlevel% neq 0 (
    echo 编译失败，请检查错误信息。
) else (
    echo 编译成功！输出文件：zns_linux_amd64_static
)
pause