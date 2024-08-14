package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/taoso/zns"
	"golang.org/x/crypto/acme/autocert"
)

const (
	DebugPort = 80
)

var tlsCert string
var tlsKey string
var tlsHosts string
var h12, h3 string
var upstream string
var dbPath string
var price int
var free bool
var root string
var debugPort int

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
			lnH12, err = net.Listen("tcp", h12)
			if err != nil {
				return
			}
		}
		if h3 != "" {
			lnH3, err = net.ListenPacket("udp", h3)
		}
	}
	return
}

func main() {
	flag.StringVar(&tlsCert, "tls-cert", "", "File path of TLS certificate")
	flag.StringVar(&tlsKey, "tls-key", "", "File path of TLS key")
	flag.StringVar(&tlsHosts, "tls-hosts", "", "Host name for ACME")
	flag.StringVar(&h12, "h12", ":443", "Listen address for http1 and h2")
	flag.StringVar(&h3, "h3", ":443", "Listen address for h3")
	flag.StringVar(&upstream, "upstream", "https://doh.pub/dns-query", "DoH upstream URL")
	flag.StringVar(&dbPath, "db", "", "File path of Sqlite database")
	flag.StringVar(&root, "root", ".", "Root path of static files")
	flag.IntVar(&price, "price", 1024, "Traffic price MB/Yuan")
	flag.BoolVar(&free, "free", false, `Whether allow free access.
If not free, you should set the following environment variables:
	- ALIPAY_APP_ID
	- ALIPAY_PRIVATE_KEY
	- ALIPAY_PUBLIC_KEY
`)
	flag.IntVar(&debugPort, "debug-port", 0, "Debug port. If set to 80, disable auto-certificate")

	flag.Parse()

	var tlsCfg *tls.Config
	if debugPort != DebugPort {
		if tlsHosts != "" {
			acm := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache(os.Getenv("HOME") + "/.autocert"),
				HostPolicy: autocert.HostWhitelist(strings.Split(tlsHosts, ",")...),
			}

			tlsCfg = acm.TLSConfig()
		} else if tlsCert != "" && tlsKey != "" {
			tlsCfg = &tls.Config{}
			certs, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
			if err != nil {
				log.Printf("Failed to load TLS certificate and key: %v", err)
				log.Println("Falling back to HTTP")
				debugPort = DebugPort
			} else {
				tlsCfg.Certificates = []tls.Certificate{certs}
			}
		} else {
			log.Println("No TLS certificate provided. Falling back to HTTP")
			debugPort = DebugPort
		}
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

	h := &zns.Handler{Upstream: upstream, Repo: repo}
	th := &zns.TicketHandler{MBpCNY: price, Pay: pay, Repo: repo}

	mux := http.NewServeMux()
	mux.Handle("/dns/{token}", h)
	mux.Handle("/ticket/", th)
	mux.Handle("/ticket/{token}", th)
	mux.Handle("/", http.FileServer(http.Dir(root)))

	if debugPort == DebugPort {
		log.Printf("Running in HTTP mode on port %d\n", DebugPort)
		if err := http.ListenAndServe(fmt.Sprintf(":%d", DebugPort), mux); err != nil {
			log.Fatal(err)
		}
	} else {
		lnH12, lnH3, err := listen()
		if err != nil {
			log.Fatal(err)
		}

		if lnH3 != nil {
			p := lnH3.LocalAddr().(*net.UDPAddr).Port
			h.AltSvc = fmt.Sprintf(`h3=":%d"`, p)
			th.AltSvc = h.AltSvc

			h3 := http3.Server{Handler: mux, TLSConfig: tlsCfg}
			go h3.Serve(lnH3)
		}

		log.Printf("Running in HTTPS mode on port %s\n", h12)
		lnTLS := tls.NewListener(lnH12, tlsCfg)
		if err = http.Serve(lnTLS, mux); err != nil {
			log.Fatal(err)
		}
	}
}