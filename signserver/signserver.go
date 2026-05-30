package signserver

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"keyless/encrypt"
	"log"
	"net/http"
	"os"
)

type SignRequest struct {
	Digest string `json:"digest"`
}
type SignResponse struct {
	Signature string `json:"signature"`
}

func StartSignServer(addr, webKeyPath, caCertPath, signCertPath, signKeyPath, password string) error {
	webKey, err := encrypt.LoadEncryptedPrivateKey(webKeyPath, password)
	if err != nil {
		return fmt.Errorf("loading encrypted private key: %w", err)
	}

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	serverCert, err := tls.LoadX509KeyPair(signCertPath, signKeyPath)
	if err != nil {
		return fmt.Errorf("loading signserver certificate: %w", err)
	}

	keyLogFile, err := os.OpenFile("signserver_mtls.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("opening keylog file: %w", err)
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
		var req SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		log.Println("Sign request: digest", req.Digest, "ip", r.Host)

		digest, err := base64.RawStdEncoding.DecodeString(req.Digest)
		if err != nil {
			http.Error(w, "bad digest", http.StatusBadRequest)
			return
		}

		sig, err := webKey.Sign(rand.Reader, digest, nil)
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}

		resp := SignResponse{
			Signature: base64.RawStdEncoding.EncodeToString(sig),
		}

		log.Println("Sign response: sign", resp.Signature)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsCfg,
		Handler:   mux,
	}

	log.Printf("Starting signserver on %s", addr)
	return fmt.Errorf("starting signserver: %w", server.ListenAndServeTLS("", ""))
}
