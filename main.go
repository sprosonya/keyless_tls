package main

import (
	"flag"
	"fmt"
	"keyless/config"
	"keyless/httpserver"
	"keyless/keyserver"
	"keyless/proxy"
	"keyless/util"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configPath := flag.String("config", "./config/config.json", "path to config file")
	mode := flag.String("mode", "", "service mode: proxy, keyserver, httpserver, encrypt, gen-certs")
	keyFile := flag.String("key", "./certs/web.key", "path to PEM private key (for encrypt mode)")
	outFile := flag.String("out", "./certs/encrypted_key.json", "output encrypted JSON file (for encrypt mode)")
	password := flag.String("password", "", "password for encryption or decryption key file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	switch *mode {
	case "encrypt":
		pass := *password
		if err := util.EncryptPrivateKey(*keyFile, pass, *outFile); err != nil {
			log.Fatalf("encryption failed: %v", err)
		}
		log.Println("encryption success")
		return

	case "genCerts":
		if err := util.GenerateCerts(cfg); err != nil {
			log.Fatalf("cert generation failed: %v", err)
		}
		log.Println("Certificates generated successfully")
		return

	case "proxy":
		if !filesExist(cfg.Proxy.WebCertFile, cfg.Proxy.MTLSCertFile,
			cfg.Proxy.MTLSKeyFile, cfg.Proxy.CACertFile) {
			log.Println("Warning: some certificate files not found")
		}
		go func() {
			log.Printf("Proxy on %s", cfg.Proxy.ListenAddr)
			if err := proxy.StartProxy(*cfg); err != nil {
				log.Fatalf("proxy error: %v", err)
			}
		}()

	case "keyserver":
		if !filesExist(cfg.KeyServer.WebPrivateKeyFile, cfg.KeyServer.ServerCertFile,
			cfg.KeyServer.ServerKeyFile, cfg.KeyServer.CACertFile) {
			log.Println("Warning: some certificate files not found")
		}
		pass := *password
		if pass == "" {
			fmt.Print("Enter password for private key: ")
			fmt.Scanln(&pass)
		}
		go func() {
			log.Printf("Keyserver on %s", cfg.KeyServer.ListenAddr)
			if err := keyserver.StartKeyServer(*cfg, pass); err != nil {
				log.Fatalf("keyserver error: %v", err)
			}
		}()

	case "httpserver":
		go func() {
			log.Printf("HTTP server on %s", cfg.HTTPServer.ListenAddr)
			if err := httpserver.StartHTTPServer(cfg.HTTPServer.ListenAddr); err != nil {
				log.Fatalf("httpserver error: %v", err)
			}
		}()

	default:
		log.Fatalf("unknown mode %q (use -mode proxy|keyserver|httpserver|encrypt)", *mode)
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
