package main

import (
	"flag"
	"fmt"
	"keyless/signserver"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "signserver address")
	webkey := flag.String("webkey", "certs/encrypted_key.json", "path to encrypted web key")
	signcert := flag.String("signcert", "certs/signserver.crt", "path to signserver certificate")
	signkey := flag.String("signkey", "certs/signserver.key", "path to signserver key")
	cacert := flag.String("cacert", "certs/ca.crt", "path to CA certificate")
	password := flag.String("password", "", "password for key decryption")
	flag.Parse()

	pass := *password
	if pass == "" {
		fmt.Print("Enter password: ")
		fmt.Scanln(&pass)
	}

	go func() {
		if err := signserver.StartSignServer(*addr, *webkey, *cacert, *signcert, *signkey, pass); err != nil {
			log.Fatalf("signserver error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down signserver")
}
