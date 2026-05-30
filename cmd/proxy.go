package main

import (
	"flag"
	"keyless/proxy"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:443", "адрес прокси")
	httpserver := flag.String("httpserver", "127.0.0.1:8080", "адрес бекенда")
	signserver := flag.String("signserver", "127.0.0.1:8443", "адрес signserver")
	webcert := flag.String("webcert", "certs/web.crt", "путь к сертификату web")
	proxycert := flag.String("proxycert", "certs/proxy.crt", "путь к сертификату прокси")
	proxykey := flag.String("proxykey", "certs/proxy.key", "путь к ключу прокси")
	cacert := flag.String("cacert", "certs/ca.crt", "путь к CA сертификату")
	flag.Parse()

	log.Printf("Proxy on %s", *addr)
	go func() {
		if err := proxy.StartProxy(*addr, *httpserver, *signserver, *webcert, *proxycert, *proxykey, *cacert); err != nil {
			log.Fatalf("error proxy: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Finishing proxy")
}
