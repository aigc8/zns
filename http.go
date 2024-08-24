package zns

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
)

const (
	fixedECSIP = "218.85.157.99"
)

func init() {
	fmt.Fprintf(os.Stdout, "ZNS服务启动时间: %s\n", time.Now().Format(time.RFC3339))
}

type Handler struct {
	Upstream string
	Repo     TicketRepo
	AltSvc   string
}

func createECS(ip net.IP) *dns.EDNS0_SUBNET {
	family := uint16(1)
	sourceNetmask := uint8(24)
	if ip.To4() == nil {
		family = 2
		sourceNetmask = 64
	}
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: sourceNetmask,
		Address:       ip,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(os.Stdout, "收到新的请求: %s %s\n", r.Method, r.URL.Path)

	if h.AltSvc != "" {
		w.Header().Set("Alt-Svc", h.AltSvc)
	}

	token := r.PathValue("token")
	if token == "" {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		fmt.Fprintf(os.Stdout, "无效的token\n")
		return
	}

	ts, err := h.Repo.List(token, 1)
	if err != nil {
		http.Error(w, "invalid token", http.StatusInternalServerError)
		fmt.Fprintf(os.Stdout, "列出token时发生错误: %v\n", err)
		return
	}
	if len(ts) == 0 || ts[0].Bytes <= 0 {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		fmt.Fprintf(os.Stdout, "无效的token或字节数不足\n")
		return
	}

	var question []byte
	if r.Method == http.MethodGet {
		q := r.URL.Query().Get("dns")
		question, err = base64.RawURLEncoding.DecodeString(q)
	} else {
		question, err = io.ReadAll(r.Body)
		r.Body.Close()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		fmt.Fprintf(os.Stdout, "读取请求体时发生错误: %v\n", err)
		return
	}

	var m dns.Msg
	if err := m.Unpack(question); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		fmt.Fprintf(os.Stdout, "解析DNS消息时发生错误: %v\n", err)
		return
	}

	// 使用固定IP
	fixedIP := net.ParseIP(fixedECSIP)
	fmt.Fprintf(os.Stdout, "使用固定IP: %s\n", fixedIP)

	// 强制替换或添加ECS选项
	opt := m.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		m.Extra = append(m.Extra, opt)
		fmt.Fprintf(os.Stdout, "添加新的OPT记录\n")
	} else {
		fmt.Fprintf(os.Stdout, "已存在OPT记录\n")
	}

	// 移除现有的ECS选项
	for i, o := range opt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			opt.Option = append(opt.Option[:i], opt.Option[i+1:]...)
			fmt.Fprintf(os.Stdout, "移除现有ECS选项\n")
			break
		}
	}

	// 添加新的ECS选项
	newECS := createECS(fixedIP)
	opt.Option = append(opt.Option, newECS)
	fmt.Fprintf(os.Stdout, "添加新的ECS选项: %+v\n", newECS)

	if question, err = m.Pack(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		fmt.Fprintf(os.Stdout, "打包DNS消息时发生错误: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "发送到上游服务器的DNS消息: %+v\n", m)

	resp, err := http.Post(h.Upstream, "application/dns-message", bytes.NewReader(question))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Fprintf(os.Stdout, "发送请求到上游服务器时发生错误: %v\n", err)
		return
	}
	defer resp.Body.Close()

	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Fprintf(os.Stdout, "读取上游服务器响应时发生错误: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "从上游服务器收到的响应长度: %d\n", len(answer))

	if err = h.Repo.Cost(token, len(question)+len(answer)); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		fmt.Fprintf(os.Stdout, "计算成本时发生错误: %v\n", err)
		return
	}

	w.Header().Add("content-type", "application/dns-message")
	w.Write(answer)
	fmt.Fprintf(os.Stdout, "请求处理完成\n")
}
