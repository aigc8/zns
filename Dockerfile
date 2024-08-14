# 使用轻量级的Alpine Linux作为基础镜像
FROM alpine:latest

# 设置工作目录
WORKDIR /app

# 复制编译好的可执行文件到容器中
COPY zns /app/zns

# 复制web目录到容器中（假设应用需要这些静态文件）
COPY web /app/web

# 设置执行权限
RUN chmod +x /app/zns

# 暴露需要的端口
EXPOSE 80 443 443/udp

# 设置启动命令
CMD ["/app/zns", "-free"]