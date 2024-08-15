package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"

	"github.com/gptq/zns"
)

// 定义监听端口常量
const (
	ListenPort = 30443
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

func listen() (lnH12 net.Listener, lnH3 net.PacketConn, err error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) {
		if os.Getenv("LISTEN_FDS") != "2" {
			return nil, nil, fmt.Errorf("LISTEN_FDS should be 2")
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
			if err != nil {
				return nil, nil, fmt.Errorf("error creating listener: %v", err)
			}
		}
	} else {
		if h12 != "" {
			lnH12, err = net.Listen("tcp", h12)
			if err != nil {
				return nil, nil, fmt.Errorf("error listening on TCP: %v", err)
			}
		}
		if h3 != "" {
			lnH3, err = net.ListenPacket("udp", h3)
			if err != nil {
				return nil, nil, fmt.Errorf("error listening on UDP: %v", err)
			}
		}
	}
	return
}

func main() {
	flag.StringVar(&tlsCert, "tls-cert", "", "File path of TLS certificate")
	flag.StringVar(&tlsKey, "tls-key", "", "File path of TLS key")
	flag.StringVar(&tlsHosts, "tls-hosts", "", "Host names for ACME, comma-separated")
	flag.StringVar(&h12, "h12", fmt.Sprintf(":%d", ListenPort), "Listen address for http1 and h2")
	flag.StringVar(&h3, "h3", fmt.Sprintf(":%d", ListenPort), "Listen address for h3")
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

	flag.Parse()

	// 验证root路径
	absRoot, err := filepath.Abs(root)
	if err != nil {
		log.Fatalf("Invalid root path: %v", err)
	}
	if _, err := os.Stat(absRoot); os.IsNotExist(err) {
		log.Fatalf("Root directory does not exist: %s", absRoot)
	}
	root = absRoot

	var tlsCfg *tls.Config
	if tlsHosts != "" {
		cfAPIToken := os.Getenv("CF_API_TOKEN")
		cfAPIEmail := os.Getenv("CF_API_EMAIL")

		if cfAPIToken == "" || cfAPIEmail == "" {
			log.Fatal("CF_API_TOKEN and CF_API_EMAIL environment variables are required for ACME DNS validation")
		}

		config := cloudflare.NewDefaultConfig()
		config.AuthToken = cfAPIToken
		config.ZoneToken = cfAPIToken
		provider, err := cloudflare.NewDNSProviderConfig(config)
		if err != nil {
			log.Fatalf("Error creating Cloudflare DNS provider: %v", err)
		}

		solver := &customDNSChallengeSolver{provider: provider}

		// 确定缓存目录
		cacheDir := ""
		if runtime.GOOS == "windows" {
			cacheDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "zns-autocert")
		} else {
			cacheDir = filepath.Join(os.Getenv("HOME"), ".zns-autocert")
		}
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			log.Fatalf("Failed to create autocert cache directory: %v", err)
		}

		acm := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cacheDir),
			HostPolicy: autocert.HostWhitelist(strings.Split(tlsHosts, ",")...),
		}

		acm.Client.DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
		acm.Client.UserAgent = "zns-acme-client/1.0"

		tlsCfg = &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err := acm.GetCertificate(hello)
				if err != nil {
					// 如果获取证书失败，使用DNS-01挑战
					if ListenPort != 443 {
						for _, host := range strings.Split(tlsHosts, ",") {
							if err := solver.Present(host, "", ""); err != nil {
								return nil, fmt.Errorf("DNS-01 challenge failed for %s: %v", host, err)
							}
							defer solver.CleanUp(host, "", "")
						}
						return acm.GetCertificate(hello)
					}
					// 如果监听端口是443，返回错误，不进行DNS-01挑战
					return nil, err
				}
				return cert, nil
			},
		}
	} else if tlsCert != "" && tlsKey != "" {
		certs, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			log.Fatalf("Error loading TLS certificate and key: %v", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{certs},
		}
	} else {
		log.Println("Warning: No TLS configuration provided. Server will run in insecure mode.")
		tlsCfg = &tls.Config{}
	}

	lnH12, lnH3, err := listen()
	if err != nil {
		log.Fatalf("Error setting up listeners: %v", err)
	}

	if lnH12 == nil && lnH3 == nil {
		log.Fatal("No valid listeners were created. Check your h12 and h3 settings.")
	}

	var pay zns.Pay
	var repo zns.TicketRepo
	if free {
		repo = zns.FreeTicketRepo{}
	} else {
		repo = zns.NewTicketRepo(dbPath)
		if repo == nil {
			log.Fatal("Failed to create TicketRepo")
		}
		pay = zns.NewPay(
			os.Getenv("ALIPAY_APP_ID"),
			os.Getenv("ALIPAY_PRIVATE_KEY"),
			os.Getenv("ALIPAY_PUBLIC_KEY"),
		)
		if pay == nil {
			log.Fatal("Failed to create Pay")
		}
	}

	h := &zns.Handler{Upstream: upstream, Repo: repo}
	th := &zns.TicketHandler{MBpCNY: price, Pay: pay, Repo: repo}

	mux := http.NewServeMux()
	mux.Handle("/dns/{token}", h)
	mux.Handle("/ticket/", th)
	mux.Handle("/ticket/{token}", th)
	mux.Handle("/", http.FileServer(http.Dir(root)))

	if lnH3 != nil {
		localAddr := lnH3.LocalAddr()
		if localAddr == nil {
			log.Println("Warning: Unable to get local address for HTTP/3 listener")
		} else {
			udpAddr, ok := localAddr.(*net.UDPAddr)
			if !ok {
				log.Printf("Warning: Unexpected address type for HTTP/3 listener: %T", localAddr)
			} else {
				h.AltSvc = fmt.Sprintf(`h3=":%d"`, udpAddr.Port)
				th.AltSvc = h.AltSvc
			}
		}

		h3 := http3.Server{Handler: mux, TLSConfig: tlsCfg}
		go func() {
			if err := h3.Serve(lnH3); err != nil {
				log.Printf("Error serving HTTP/3: %v", err)
			}
		}()
	} else {
		log.Println("HTTP/3 listener not available")
	}

	if lnH12 != nil {
		lnTLS := tls.NewListener(lnH12, tlsCfg)
		log.Println("Starting server...")
		if err = http.Serve(lnTLS, mux); err != nil {
			log.Fatalf("Error serving HTTP/1.1 and HTTP/2: %v", err)
		}
	} else {
		log.Println("HTTP/1.1 and HTTP/2 listener not available. Only serving HTTP/3 if available.")
		select {} // Keep the program running for HTTP/3
	}
}

type customDNSChallengeSolver struct {
	provider *cloudflare.DNSProvider
}

func (s *customDNSChallengeSolver) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	return s.provider.Present(domain, fqdn, value)
}

func (s *customDNSChallengeSolver) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	return s.provider.CleanUp(domain, fqdn, "")
}