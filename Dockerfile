# 使用官方Go镜像作为构建阶段
FROM golang:1.22-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的构建工具
RUN apk add --no-cache git

# 复制go mod和sum文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -v -o zns ./cmd/zns

# 使用轻量级的alpine作为最终镜像
FROM alpine:latest

# 安装ca-certificates，这对HTTPS可能是必要的
RUN apk --no-cache add ca-certificates

# 创建非root用户
RUN adduser -D -u 1000 appuser

# 设置工作目录
WORKDIR /app

# 从builder阶段复制编译好的二进制文件
COPY --from=builder /app/zns .

# 创建证书目录
RUN mkdir /app/certs

# 复制web目录
COPY web /app/web

# 更改所有权
RUN chown -R appuser:appuser /app

# 切换到非root用户
USER appuser

# 暴露端口（根据需要调整）
EXPOSE 37443

# 设置入口点
ENTRYPOINT ["./zns"]

# 设置默认命令参数
CMD ["-tls-cert", "/app/certs/fullchain.pem", "-tls-key", "/app/certs/privkey.pem", "-root", "/app/web"]