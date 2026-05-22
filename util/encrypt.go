package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/scrypt"
)

type EncryptedKeyData struct {
	Nonce string `json:"nonce"`
	Key   string `json:"key"`
}

func EncryptPrivateKey(keyPath, password, outPath string) error {
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("cannot read key file: %w", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("no PEM block found")
	}

	// фиксированная соль
	//
	salt := sha256.Sum256([]byte("keyless-tls"))

	// KDF: scrypt
	key, err := scrypt.Key([]byte(password), salt[:], 1<<15, 8, 1, 32)
	if err != nil {
		return fmt.Errorf("scrypt: %w", err)
	}

	// случайный nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("rand: %w", err)
	}

	// AES-GCM
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, block.Bytes, nil)

	// запись в JSON
	ek := EncryptedKeyData{
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		Key:   base64.StdEncoding.EncodeToString(ciphertext),
	}
	jsonData, err := json.Marshal(ek)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	if err := os.WriteFile(outPath, jsonData, 0600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

func LoadEncryptedPrivateKey(path, password string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read encrypted key file: %w", err)
	}
	var ek EncryptedKeyData
	if err := json.Unmarshal(data, &ek); err != nil {
		return nil, fmt.Errorf("invalid encrypted key format: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(ek.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ek.Key)
	if err != nil {
		return nil, fmt.Errorf("invalid cipher: %w", err)
	}

	// фиксированная соль
	salt := sha256.Sum256([]byte("keyless-tls"))

	// KDF
	key, err := scrypt.Key([]byte(password), salt[:], 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return x509.ParseECPrivateKey(plaintext)
}
