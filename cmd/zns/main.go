package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/mholt/acmez/v2"
	"github.com/mholt/acmez/v2/acme"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/atomic"
	"go.uber.org/zap"

	"github.com/gptq/zns"
)

// 定义监听端口常量
const (
	ListenPort = 30443
)

var (
	tlsCert     string
	tlsKey      string
	tlsHosts    string
	h12, h3     string
	upstream    string
	dbPath      string
	price       int
	free        bool
	root        string
	ownerEmail  string
	cfAPIToken  string
	production  bool
	logger      *zap.Logger
)

type Autocert struct {
	domains            []string
	ownerEmail         []string
	cloudflareAPIToken string
	privateKey         *ecdsa.PrivateKey
	certs              []acme.Certificate
	inProcess          *atomic.Bool
	prod               bool
}

func NewAutocert(domains []string, ownerEmail string, cloudflareAPIToken string, prod bool) *Autocert {
	return &Autocert{
		domains:            domains,
		ownerEmail:         []string{ownerEmail},
		cloudflareAPIToken: cloudflareAPIToken,
		inProcess:          atomic.NewBool(false),
		prod:               prod,
	}
}

func (a *Autocert) RequestCertificate(ctx context.Context) (err error) {
	if !a.inProcess.CompareAndSwap(false, true) {
		return
	}
	defer a.inProcess.Store(false)

	logger.Info("Requesting certificate", zap.Strings("domains", a.domains))

	solver := &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: &cloudflare.Provider{
				APIToken: a.cloudflareAPIToken,
			},
		},
	}

	caLocation := certmagic.LetsEncryptStagingCA
	if a.prod {
		caLocation = certmagic.LetsEncryptProductionCA
	}

	client := acmez.Client{
		Client: &acme.Client{
			Directory: caLocation,
			Logger:    logger,
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeDNS01: solver,
		},
	}

	var accountPrivateKey *ecdsa.PrivateKey
	accountPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Wrap(err, "could not generate an account key")
	}

	account := acme.Account{
		Contact:              a.ownerEmail,
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}

	var acc acme.Account
	acc, err = client.NewAccount(ctx, account)
	if err != nil {
		return errors.Wrap(err, "could not create new account")
	}

	a.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Wrap(err, "generating certificate key")
	}

	a.certs, err = client.ObtainCertificateForSANs(ctx, acc, a.privateKey, a.domains)
	if err != nil {
		return errors.Wrap(err, "could not obtain certificate")
	}

	logger.Info("Certificate obtained successfully")
	return nil
}

func (a *Autocert) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if len(a.certs) == 0 {
		return nil, fmt.Errorf("no certificates available")
	}

	certPEM := a.certs[0].ChainPEM
	keyPEM, err := x509.MarshalECPrivateKey(a.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})

	cert, err := tls.X509KeyPair(certPEM, keyPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to load keypair: %v", err)
	}

	return &cert, nil
}

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
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	flag.StringVar(&tlsCert, "tls-cert", "", "File path of TLS certificate")
	flag.StringVar(&tlsKey, "tls-key", "", "File path of TLS key")
	flag.StringVar(&tlsHosts, "tls-hosts", "", "Host names for ACME, comma-separated")
	flag.StringVar(&h12, "h12", fmt.Sprintf(":%d", ListenPort), "Listen address for http1 and h2")
	flag.StringVar(&h3, "h3", fmt.Sprintf(":%d", ListenPort), "Listen address for h3")
	flag.StringVar(&upstream, "upstream", "https://doh.pub/dns-query", "DoH upstream URL")
	flag.StringVar(&dbPath, "db", "", "File path of Sqlite database")
	flag.StringVar(&root, "root", ".", "Root path of static files")
	flag.IntVar(&price, "price", 1024, "Traffic price MB/Yuan")
	flag.BoolVar(&free, "free", false, "Whether allow free access")
	flag.StringVar(&ownerEmail, "email", "", "Email address for Let's Encrypt")
	flag.StringVar(&cfAPIToken, "cf-token", "", "Cloudflare API Token")
	flag.BoolVar(&production, "prod", false, "Use Let's Encrypt production server")

	flag.Parse()

	// 验证root路径
	absRoot, err := filepath.Abs(root)
	if err != nil {
		logger.Fatal("Invalid root path", zap.Error(err))
	}
	if _, err := os.Stat(absRoot); os.IsNotExist(err) {
		logger.Fatal("Root directory does not exist", zap.String("path", absRoot))
	}
	root = absRoot

	var tlsCfg *tls.Config
	if tlsHosts != "" {
		if ownerEmail == "" || cfAPIToken == "" {
			logger.Fatal("Email and Cloudflare API Token are required for automatic certificate management")
		}

		domains := strings.Split(tlsHosts, ",")
		autocert := NewAutocert(domains, ownerEmail, cfAPIToken, production)

		if err := autocert.RequestCertificate(context.Background()); err != nil {
			logger.Fatal("Failed to request certificate", zap.Error(err))
		}

		tlsCfg = &tls.Config{
			GetCertificate: autocert.GetCertificate,
		}
	} else if tlsCert != "" && tlsKey != "" {
		certs, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			logger.Fatal("Error loading TLS certificate and key", zap.Error(err))
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{certs},
		}
	} else {
		logger.Warn("No TLS configuration provided. Server will run in insecure mode.")
		tlsCfg = &tls.Config{}
	}

	lnH12, lnH3, err := listen()
	if err != nil {
		logger.Fatal("Error setting up listeners", zap.Error(err))
	}

	if lnH12 == nil && lnH3 == nil {
		logger.Fatal("No valid listeners were created. Check your h12 and h3 settings.")
	}

	var pay zns.Pay
	var repo zns.TicketRepo
	if free {
		repo = zns.FreeTicketRepo{}
	} else {
		repo = zns.NewTicketRepo(dbPath)
		if repo == nil {
			logger.Fatal("Failed to create TicketRepo")
		}
		pay = zns.NewPay(
			os.Getenv("ALIPAY_APP_ID"),
			os.Getenv("ALIPAY_PRIVATE_KEY"),
			os.Getenv("ALIPAY_PUBLIC_KEY"),
		)
		if pay == nil {
			logger.Fatal("Failed to create Pay")
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
			logger.Warn("Unable to get local address for HTTP/3 listener")
		} else {
			udpAddr, ok := localAddr.(*net.UDPAddr)
			if !ok {
				logger.Warn("Unexpected address type for HTTP/3 listener", zap.String("type", fmt.Sprintf("%T", localAddr)))
			} else {
				h.AltSvc = fmt.Sprintf(`h3=":%d"`, udpAddr.Port)
				th.AltSvc = h.AltSvc
			}
		}

		h3 := http3.Server{Handler: mux, TLSConfig: tlsCfg}
		go func() {
			if err := h3.Serve(lnH3); err != nil {
				logger.Error("Error serving HTTP/3", zap.Error(err))
			}
		}()
	} else {
		logger.Warn("HTTP/3 listener not available")
	}

	if lnH12 != nil {
		lnTLS := tls.NewListener(lnH12, tlsCfg)
		logger.Info("Starting server...")
		if err = http.Serve(lnTLS, mux); err != nil {
			logger.Fatal("Error serving HTTP/1.1 and HTTP/2", zap.Error(err))
		}
	} else {
		logger.Warn("HTTP/1.1 and HTTP/2 listener not available. Only serving HTTP/3 if available.")
		select {} // Keep the program running for HTTP/3
	}
}