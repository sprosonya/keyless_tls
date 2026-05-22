package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/scrypt"
)

type encryptedKeyData struct {
	Nonce string `json:"nonce"`
	Key   string `json:"key"`
}

func main() {
	keyFile := flag.String("key", "web.key", "Путь к приватному ключу в формате PEM")
	outFile := flag.String("out", "encrypted_key.json", "Имя файла с зашифрованным ключом")
	flag.Parse()

	if *keyFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	pass := make([]byte, 0)
	fmt.Print("Введите пароль для зашифрования: ")
	fmt.Scanln(&pass)

	pemData, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("Error reading key file %v\n", err)
		os.Exit(1)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatalf("PEM decoding error")
		os.Exit(1)
	}

	//фиксированная соль
	h := sha256.Sum256([]byte("keyless_tls"))

	// KDF
	key, err := scrypt.Key(pass, h[:], 1<<15, 8, 1, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scrypt error: %v\n", err)
		os.Exit(1)
	}

	// генерация случайного nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// AES-GCM
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		panic(err)
	}
	ciphertext := aead.Seal(nil, nonce, block.Bytes, nil)

	ed := encryptedKeyData{
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		Key:   base64.StdEncoding.EncodeToString(ciphertext),
	}
	jsonData, err := json.Marshal(ed)
	if err != nil {
		log.Fatalf("Failed to marshal: %v\n", err)
	}

	if err := os.WriteFile(*outFile, jsonData, 0600); err != nil {
		log.Fatalf("Failed to write key: %v\n", err)
		os.Exit(1)
	}
}
