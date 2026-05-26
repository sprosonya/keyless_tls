package keyserver

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"keyless/config"
	"keyless/util"
	"log"
	"net/http"
	"os"
)

func StartKeyServer(cfg config.Config, password string) error {
	// загрузка приватного ключа
	//KDF от пароля
	//файл json с полями 1) вектор инициализации nonce 2) ключ
	//AES-GCM

	webKey, err := util.LoadEncryptedPrivateKey(cfg.Certificates.WebEncryptedKeyFile, password)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// загрузка сертификата CA
	caPEM, err := os.ReadFile(cfg.Certificates.CACertFile)
	if err != nil {
		return err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	//загрузка пары сертификат/ключ для хранилища для mTLS
	serverCert, err := tls.LoadX509KeyPair(cfg.Certificates.KeyServerCertFile, cfg.Certificates.KeyServerKeyFile)
	if err != nil {
		return err
	}
	//экспорт сессионных ключей для расшифровки
	keyLogFile, err := os.OpenFile("keyserver_tls_keys.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("cannot open keylog file: %w", err)
	}
	defer keyLogFile.Close()

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
		KeyLogWriter: keyLogFile,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Digest string `json:"digest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		log.Println("Sign request: digest", req.Digest, "ip", r.Host)
		//читаем хэш
		digest, err := base64.RawStdEncoding.DecodeString(req.Digest)
		if err != nil {
			http.Error(w, "bad digest", http.StatusBadRequest)
			return
		}
		//подписываем приватным ключом хэш
		sig, err := webKey.Sign(rand.Reader, digest, nil)
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		resp := struct {
			Signature string `json:"signature"`
		}{
			Signature: base64.RawStdEncoding.EncodeToString(sig),
		}
		log.Println("Sign response: sign", resp.Signature)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server := &http.Server{
		Addr:      cfg.Servers.KeyServerAddr,
		TLSConfig: tlsCfg,
		Handler:   mux,
	}
	return server.ListenAndServeTLS("", "")
}
