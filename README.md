# ZNS - 简单的Go语言DoH服务器

ZNS是一个用Go语言编写的简单DNS over HTTPS (DoH)服务器。它提供了一种安全的方式来进行DNS查询，通过HTTPS协议加密DNS请求和响应。

## 特性

- 支持DNS over HTTPS (DoH)协议
- 轻量级和高性能
- 可配置的TLS主机
- 支持自定义根目录
- Docker支持
- 支持根据域名选择不同的上游DNS服务器（中国域名和非中国域名）

## 安装

### 使用Go安装

确保你已经安装了Go 1.16或更高版本，然后运行以下命令：

```bash
go install github.com/taoso/zns/cmd/zns@latest
```

### 使用Docker

项目包含一个Dockerfile，你可以使用以下命令构建Docker镜像：

```bash
docker build -t zns .
```

## 运行

### 命令行运行

```bash
zns -free -tls-hosts zns.example.org -root /var/www/html -default-upstream https://doh.pub/dns-query -china-upstream https://doh.pub/dns-query -china-domain-list /path/to/china_domain_list.txt -public-suffix-list /path/to/public_suffix_list.dat
```

参数说明：
- `-free`: 启用免费模式（具体功能需要补充）
- `-tls-hosts`: 指定TLS主机名，用于HTTPS连接
- `-root`: 指定根目录路径
- `-default-upstream`: 指定默认的上游DoH服务器URL
- `-china-upstream`: 指定用于中国域名的上游DoH服务器URL
- `-china-domain-list`: 指定中国域名列表文件的路径
- `-public-suffix-list`: 指定公共后缀列表文件的路径

### 使用Docker运行

```bash
docker run -p 443:443 -v /path/to/your/data:/var/www/html -v /path/to/china_domain_list.txt:/etc/zns/china_domain_list.txt -v /path/to/public_suffix_list.dat:/etc/zns/public_suffix_list.dat zns -free -tls-hosts zns.example.org -root /var/www/html -default-upstream https://doh.pub/dns-query -china-upstream https://doh.pub/dns-query -china-domain-list /etc/zns/china_domain_list.txt -public-suffix-list /etc/zns/public_suffix_list.dat
```

## 配置

ZNS支持多种配置选项，您可以通过命令行参数进行设置。主要的配置选项包括：

- 默认上游DoH服务器
- 中国域名专用上游DoH服务器
- 中国域名列表文件
- 公共后缀列表文件

确保在运行ZNS之前，准备好中国域名列表文件和公共后缀列表文件。您可以从以下地方获取这些文件：

- 中国域名列表：[dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)
- 公共后缀列表：[Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat)

## 工作原理

ZNS使用预编译的中国域名列表和公共后缀列表来判断一个域名是否为中国域名。如果是中国域名，它会使用指定的中国上游DoH服务器进行查询；否则，它会使用默认的上游DoH服务器。这样可以优化中国用户的DNS查询体验，同时保持对国际域名的良好支持。

## 贡献

我们欢迎任何形式的贡献！如果你发现了bug或有改进建议，请创建一个issue或提交一个pull request。

## 许可证

本项目采用MIT许可证。详情请见[LICENSE](LICENSE)文件。

## 联系方式

如果您有任何问题或建议，请通过GitHub issue与我们联系。

---

注意：请定期更新中国域名列表和公共后缀列表，以确保域名判断的准确性。
