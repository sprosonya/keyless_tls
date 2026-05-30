package main

import (
	"flag"
	"keyless/httpserver"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "httpserver address")
	flag.Parse()

	log.Printf("HTTP-server on %s", *addr)
	go func() {
		if err := httpserver.StartHTTPServer(*addr); err != nil {
			log.Fatalf("error HTTP: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Finishing HTTP-server")
}
