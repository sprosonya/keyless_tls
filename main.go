package main

import (
	"flag"
	"fmt"
	"keyless/config"
	"keyless/httpserver"
	"keyless/proxy"
	"keyless/signserver"
	"keyless/util"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configPath := flag.String("config", "./config/config.json", "path to config file")
	mode := flag.String("mode", "", "service mode: proxy, keyserver, httpserver, encrypt, gen-certs")
	password := flag.String("password", "", "password for encryption or decryption key file")
	webCertKey := flag.Bool("skip-web-gen", false, "enable web certificate")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	switch *mode {
	case "encrypt":
		pass := *password
		if pass == "" {
			fmt.Print("Enter password for private key: ")
			fmt.Scanln(&pass)
		}
		if err := util.EncryptPrivateKey(cfg.Certificates.WebKeyFile, pass, cfg.Certificates.WebEncryptedKeyFile); err != nil {
			log.Fatalf("encryption error: %v", err)
		}
		log.Println("encryption success")
		return

	case "gen-certs":
		if err := util.GenerateCerts(cfg, *webCertKey); err != nil {
			log.Fatalf("cert generation error: %v", err)
		}
		log.Println("Certificates generated successfully")
		return

	case "proxy":
		if !filesExist(cfg.Certificates.WebCertFile, cfg.Certificates.ProxyCertFile,
			cfg.Certificates.ProxyKeyFile, cfg.Certificates.CACertFile) {
			log.Println("Warning: some certificate files not found")
		}
		go func() {
			log.Printf("Proxy on %s", cfg.Servers.ProxyAddr)
			if err := proxy.StartProxy(*cfg); err != nil {
				log.Fatalf("proxy error: %v", err)
			}
		}()

	case "keyserver":
		if !filesExist(cfg.Certificates.WebEncryptedKeyFile, cfg.Certificates.SignServerCertFile,
			cfg.Certificates.SignServerKeyFile, cfg.Certificates.CACertFile) {
			log.Println("Warning: some certificate files not found")
		}
		pass := *password
		if pass == "" {
			fmt.Print("Enter password for private key: ")
			fmt.Scanln(&pass)
		}
		go func() {
			log.Printf("Signserver on %s", cfg.Servers.SignServerAddr)
			if err := signserver.StartSignServer(*cfg, pass); err != nil {
				log.Fatalf("signserver error: %v", err)
			}
		}()

	case "httpserver":
		go func() {
			log.Printf("HTTP server on %s", cfg.Servers.HTTPServerAddr)
			if err := httpserver.StartHTTPServer(cfg.Servers.HTTPServerAddr); err != nil {
				log.Fatalf("httpserver error: %v", err)
			}
		}()

	default:
		log.Fatalf("unknown mode %q", *mode)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")
}

func filesExist(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return false
		}
	}
	return true
}
