package main

import (
	"flag"
	"fmt"
	"keyless/encrypt"
	"log"
)

func main() {
	key := flag.String("key", "certs/web.key", "path to PEM key")
	out := flag.String("out", "certs/encrypted_key.json", "out file")
	password := flag.String("password", "", "password")
	flag.Parse()

	pass := *password
	if pass == "" {
		fmt.Print("Enter password: ")
		fmt.Scanln(&pass)
	}

	if err := encrypt.EncryptPrivateKey(*key, pass, *out); err != nil {
		log.Fatalf("error encrypting: %v", err)
	}
	log.Println("Successfully encrypted")
}
