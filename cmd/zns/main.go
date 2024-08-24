package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

var tlsCert string
var tlsKey string
var h12, h3 string
var upstream string
var dbPath string
var price int
var free bool
var root string

const (
	fixedECSIP = "218.85.157.99"
)

// Pay 结构体定义
type Pay struct {
	AppID      string
	PrivateKey string
	PublicKey  string
}

// TicketRepo 接口定义
type TicketRepo interface {
	List(token string, limit int) ([]Ticket, error)
	Cost(token string, bytes int) error
}

// Ticket 结构体定义
type Ticket struct {
	Bytes int
}

// FreeTicketRepo 结构体定义
type FreeTicketRepo struct{}

func (f FreeTicketRepo) List(token string, limit int) ([]Ticket, error) {
	return []Ticket{{Bytes: 1000000}}, nil
}

func (f FreeTicketRepo) Cost(token string, bytes int) error {
	return nil
}

// Handler 结构体定义
type Handler struct {
	Upstream string
	Repo     TicketRepo
	AltSvc   string
}

// TicketHandler 结构体定义
type TicketHandler struct {
	MBpCNY int
	Pay    Pay
	Repo   TicketRepo
	AltSvc string
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

	// 使用固定IP
	fixedIP := net.ParseIP(fixedECSIP)

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

func (th *TicketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 实现 TicketHandler 的 ServeHTTP 方法
	// 这里需要根据原有的实现来补充
}

func NewTicketRepo(dbPath string) TicketRepo {
	// 实现 NewTicketRepo 函数
	return &FreeTicketRepo{} // 临时返回 FreeTicketRepo，实际应该根据 dbPath 创建一个数据库连接的 TicketRepo
}

func listen() (lnH12 net.Listener, lnH3 net.PacketConn, err error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) {
		if os.Getenv("LISTEN_FDS") != "2" {
			panic("LISTEN_FDS should be 2")
		}
		names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
		for i, name := range names {
			switch name {
			case "h12":
				f := os.NewFile(uintptr(i+3), "https port")
				lnH12, err = net.FileListener(f)
			case "h3":
				f := os.NewFile(uintptr(i+3), "quic port")
				lnH3, err = net.FilePacketConn(f)
			}
		}
	} else {
		if h12 != "" {
			lnH12, err = net.Listen("tcp", ":"+h12)
			if err != nil {
				return
			}
		}
		if h3 != "" {
			lnH3, err = net.ListenPacket("udp", ":"+h3)
			if err == nil {
				err = increaseUDPBufferSize(lnH3)
			}
		}
	}
	return
}

func increaseUDPBufferSize(conn net.PacketConn) error {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("not a UDP connection")
	}

	file, err := udpConn.File()
	if err != nil {
		return err
	}
	defer file.Close()

	fd := file.Fd()
	var desiredSize int = 2048 * 1024 // 2MB

	return setSockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, desiredSize)
}

func NewPay(appID, privateKey, publicKey string) Pay {
	return Pay{
		AppID:      appID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

func main() {
	flag.StringVar(&tlsCert, "tls-cert", "", "File path of TLS certificate")
	flag.StringVar(&tlsKey, "tls-key", "", "File path of TLS key")
	flag.StringVar(&h12, "h12", "37443", "Listen port for http1 and h2")
	flag.StringVar(&h3, "h3", "37443", "Listen port for h3")
	flag.StringVar(&upstream, "upstream", "https://doh.pub/dns-query", "DoH upstream URL")
	flag.StringVar(&dbPath, "db", "", "File path of Sqlite database")
	flag.StringVar(&root, "root", ".", "Root path of static files")
	flag.IntVar(&price, "price", 1024, "Traffic price MB/Yuan")
	flag.BoolVar(&free, "free", true, `Whether allow free access.
If not free, you should set the following environment variables:
	- ALIPAY_APP_ID
	- ALIPAY_PRIVATE_KEY
	- ALIPAY_PUBLIC_KEY
`)

	flag.Parse()

	tlsCfg := &tls.Config{}
	certs, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		panic(err)
	}
	tlsCfg.Certificates = []tls.Certificate{certs}

	lnH12, lnH3, err := listen()
	if err != nil {
		panic(err)
	}

	var pay Pay
	var repo TicketRepo
	if free {
		repo = FreeTicketRepo{}
	} else {
		repo = NewTicketRepo(dbPath)
		pay = NewPay(
			os.Getenv("ALIPAY_APP_ID"),
			os.Getenv("ALIPAY_PRIVATE_KEY"),
			os.Getenv("ALIPAY_PUBLIC_KEY"),
		)
	}

	h := &Handler{Upstream: upstream, Repo: repo}
	th := &TicketHandler{MBpCNY: price, Pay: pay, Repo: repo}

	mux := http.NewServeMux()
	mux.Handle("/dns/{token}", h)
	mux.Handle("/ticket/", th)
	mux.Handle("/ticket/{token}", th)
	mux.Handle("/", http.FileServer(http.Dir(root)))

	if lnH3 != nil {
		p := lnH3.LocalAddr().(*net.UDPAddr).Port
		h.AltSvc = fmt.Sprintf(`h3=":%d"`, p)
		th.AltSvc = h.AltSvc

		h3 := http3.Server{Handler: mux, TLSConfig: tlsCfg}
		go h3.Serve(lnH3)
	}

	lnTLS := tls.NewListener(lnH12, tlsCfg)
	if err = http.Serve(lnTLS, mux); err != nil {
		log.Fatal(err)
	}
}
