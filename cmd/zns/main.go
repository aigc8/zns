package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/aigc8/zns"
	"github.com/quic-go/quic-go/http3"
)

var tlsCert string
var tlsKey string
var h12, h3 string
var defaultUpstream string
var chinaUpstream string
var dbPath string
var price int
var free bool
var root string
var chinaDomainListPath string
var publicSuffixListPath string

func init() {
	// 关闭日志输出
	log.SetOutput(io.Discard)
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
			if err != nil {
				return
			}
		}
	}
	return
}

func main() {
	flag.StringVar(&tlsCert, "tls-cert", "", "File path of TLS certificate")
	flag.StringVar(&tlsKey, "tls-key", "", "File path of TLS key")
	flag.StringVar(&h12, "h12", "37443", "Listen port for http1 and h2")
	flag.StringVar(&h3, "h3", "37443", "Listen port for h3")
	flag.StringVar(&defaultUpstream, "default-upstream", "https://doh.pub/dns-query", "Default DoH upstream URL")
	flag.StringVar(&chinaUpstream, "china-upstream", "https://doh.pub/dns-query", "China DoH upstream URL")
	flag.StringVar(&dbPath, "db", "", "File path of Sqlite database")
	flag.StringVar(&root, "root", ".", "Root path of static files")
	flag.IntVar(&price, "price", 1024, "Traffic price MB/Yuan")
	flag.BoolVar(&free, "free", true, `Whether allow free access.
If not free, you should set the following environment variables:
	- ALIPAY_APP_ID
	- ALIPAY_PRIVATE_KEY
	- ALIPAY_PUBLIC_KEY
`)
	flag.StringVar(&chinaDomainListPath, "china-domain-list", "", "Path to China domain list file")
	flag.StringVar(&publicSuffixListPath, "public-suffix-list", "", "Path to public suffix list file")

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

	var pay zns.Pay
	var repo zns.TicketRepo
	if free {
		repo = zns.FreeTicketRepo{}
	} else {
		repo = zns.NewTicketRepo(dbPath)
		pay = zns.NewPay(
			os.Getenv("ALIPAY_APP_ID"),
			os.Getenv("ALIPAY_PRIVATE_KEY"),
			os.Getenv("ALIPAY_PUBLIC_KEY"),
		)
	}

	chinaDomainChecker := zns.NewChinaDomainChecker()
	if err := chinaDomainChecker.LoadDomainList(chinaDomainListPath); err != nil {
		log.Fatalf("Failed to load China domain list: %v", err)
	}
	if err := chinaDomainChecker.LoadSuffixList(publicSuffixListPath); err != nil {
		log.Fatalf("Failed to load public suffix list: %v", err)
	}

	h := &zns.Handler{
		DefaultUpstream:   defaultUpstream,
		ChinaUpstream:     chinaUpstream,
		Repo:              repo,
		FreeMode:          free,
		ChinaDomainChecker: chinaDomainChecker,
	}
	th := &zns.TicketHandler{MBpCNY: price, Pay: pay, Repo: repo}

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
		os.Exit(1)
	}
}
