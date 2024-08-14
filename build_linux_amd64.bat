@echo off
REM 设置环境变量以进行交叉编译
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0

REM 编译 Go 程序
go build -ldflags "-extldflags '-static'" -o zns  ./cmd/zns


REM 提示编译完成
echo 编译完成！
pause
