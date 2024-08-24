package zns

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

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
		sourceNetmask = 48
	}
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: sourceNetmask,
		Address:       ip,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.AltSvc != "" {
		w.Header().Set("Alt-Svc", h.AltSvc)
	}

	token := r.PathValue("token")
	if token == "" {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	ts, err := h.Repo.List(token, 1)
	if err != nil {
		http.Error(w, "invalid token", http.StatusInternalServerError)
		return
	}
	if len(ts) == 0 || ts[0].Bytes <= 0 {
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var m dns.Msg
	if err := m.Unpack(question); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 默认使用IPv4固定IP
	fixedIP := net.ParseIP("218.85.157.99")

	// 尝试获取客户端IP，只用于判断是否为IPv6
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		ip := net.ParseIP(clientIP)
		if ip != nil && ip.To4() == nil {
			// 如果客户端是IPv6，则使用IPv6固定IP
			fixedIP = net.ParseIP("240e:14:6000::1")
		}
	}

	// 强制替换或添加ECS选项
	opt := m.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		m.Extra = append(m.Extra, opt)
	}

	// 移除现有的ECS选项
	for i, o := range opt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			opt.Option = append(opt.Option[:i], opt.Option[i+1:]...)
			break
		}
	}

	// 添加新的ECS选项
	opt.Option = append(opt.Option, createECS(fixedIP))

	if question, err = m.Pack(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := http.Post(h.Upstream, "application/dns-message", bytes.NewReader(question))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = h.Repo.Cost(token, len(question)+len(answer)); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Add("content-type", "application/dns-message")
	w.Write(answer)
}
