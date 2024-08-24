package zns

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
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
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.Println("ZNS包初始化时间:", time.Now().Format(time.RFC3339))
}

type Handler struct {
	Upstream string
	Repo     TicketRepo
	AltSvc   string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	log.Printf("收到新的请求: %s %s", r.Method, r.URL.Path)
	defer func() {
		log.Printf("请求处理完成，耗时: %v", time.Since(startTime))
	}()

	if h.AltSvc != "" {
		w.Header().Set("Alt-Svc", h.AltSvc)
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		log.Println("无效的token")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	ts, err := h.Repo.List(token, 1)
	if err != nil {
		log.Printf("列出token时发生错误: %v", err)
		http.Error(w, "invalid token", http.StatusInternalServerError)
		return
	}
	if len(ts) == 0 || ts[0].Bytes <= 0 {
		log.Println("无效的token或字节数不足")
		http.Error(w, "invalid token", http.StatusUnauthorized)
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
		log.Printf("读取请求体时发生错误: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var m dns.Msg
	if err := m.Unpack(question); err != nil {
		log.Printf("解析DNS消息时发生错误: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 使用固定IP
	fixedIP := net.ParseIP(fixedECSIP)
	log.Printf("使用固定IP: %s", fixedIP)

	// 强制替换或添加ECS选项
	opt := m.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		m.Extra = append(m.Extra, opt)
		log.Println("添加新的OPT记录")
	} else {
		log.Println("已存在OPT记录")
	}

	// 移除现有的ECS选项
	for i, o := range opt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			opt.Option = append(opt.Option[:i], opt.Option[i+1:]...)
			log.Println("移除现有ECS选项")
			break
		}
	}

	// 添加新的ECS选项
	newECS := createECS(fixedIP)
	opt.Option = append(opt.Option, newECS)
	log.Printf("添加新的ECS选项: %+v", newECS)

	if question, err = m.Pack(); err != nil {
		log.Printf("打包DNS消息时发生错误: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("发送到上游服务器的DNS消息: %+v", m)

	resp, err := http.Post(h.Upstream, "application/dns-message", bytes.NewReader(question))
	if err != nil {
		log.Printf("发送请求到上游服务器时发生错误: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取上游服务器响应时发生错误: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("从上游服务器收到的响应长度: %d", len(answer))

	if err = h.Repo.Cost(token, len(question)+len(answer)); err != nil {
		log.Printf("计算成本时发生错误: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Add("content-type", "application/dns-message")
	w.Write(answer)
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
