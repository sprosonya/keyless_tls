package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"flag"
	"keyless/gencerts"
	"log"
	"os"
	"path/filepath"
)

const (
	caCertFile    = "ca.crt"
	caKeyFile     = "ca.key"
	proxyCertFile = "proxy.crt"
	proxyKeyFile  = "proxy.key"
	signCertFile  = "signserver.crt"
	signKeyFile   = "signserver.key"
	webCertFile   = "web.crt"
	webKeyFile    = "web.key"
)

func main() {
	mode := flag.String("mode", "", "mode: ca, proxy, signserver, web, all")
	dir := flag.String("dir", "certs", "certificate directory")
	proxyIP := flag.String("proxy-ip", "127.0.0.1", "IP proxy")
	signIP := flag.String("sign-ip", "127.0.0.1", "IP signserver")
	webIP := flag.String("web-ip", "127.0.0.1", "IP web")
	flag.Parse()

	if *mode == "" {
		log.Fatal("Use -mode (ca, proxy, signserver, web, all)")
	}

	genCA := *mode == "ca" || *mode == "all"
	genProxy := *mode == "proxy" || *mode == "all"
	genSign := *mode == "signserver" || *mode == "all"
	genWeb := *mode == "web" || *mode == "all"

	if err := os.MkdirAll(*dir, 0755); err != nil {
		log.Fatalf("Error creating dir: %v", err)
	}

	caCertPath := filepath.Join(*dir, caCertFile)
	caKeyPath := filepath.Join(*dir, caKeyFile)

	var caCert *x509.Certificate
	var caKey *ecdsa.PrivateKey

	if genCA {
		caKey, caCert = gencerts.GenerateCA(caCertPath, caKeyPath)
	} else {
		var err error
		caCert, err = gencerts.LoadCertificate(caCertPath)
		if err != nil {
			log.Fatalf("Error downloading CA cert: %v", err)
		}
		caKey, err = gencerts.LoadECPrivateKey(caKeyPath)
		if err != nil {
			log.Fatalf("Error downloading CA key: %v", err)
		}
	}

	if genProxy {
		gencerts.GenerateProxyCert(filepath.Join(*dir, proxyCertFile), filepath.Join(*dir, proxyKeyFile), caCert, caKey, *proxyIP)
	}
	if genSign {
		gencerts.GenerateSignServerCert(filepath.Join(*dir, signCertFile), filepath.Join(*dir, signKeyFile), caCert, caKey, *signIP)
	}
	if genWeb {
		gencerts.GenerateWebCert(filepath.Join(*dir, webCertFile), filepath.Join(*dir, webKeyFile), caCert, caKey, *webIP)
	}

	log.Println("Successful generating")
}
