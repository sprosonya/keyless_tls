package proxy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"keyless/config"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

// реализация Signer
type RemoteSigner struct {
	publicKey *ecdsa.PublicKey
	client    *http.Client
	signURL   string
}

func (rs *RemoteSigner) Public() crypto.PublicKey {
	return rs.publicKey
}

func (rs *RemoteSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	reqBody := struct {
		Digest string `json:"digest"`
	}{
		Digest: base64.RawStdEncoding.EncodeToString(digest),
	}
	data, _ := json.Marshal(reqBody)
	log.Println("Send sign request. Digest:", reqBody.Digest)
	resp, err := rs.client.Post(rs.signURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keyserver error: %s", resp.Status)
	}
	var reply struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return base64.RawStdEncoding.DecodeString(reply.Signature)
}

func StartProxy(cfg config.Config) error {
	// загрузка сертификата бекенда
	webCertPEM, err := os.ReadFile(cfg.Certificates.WebCertFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(webCertPEM)
	webCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	pubKey, _ := webCert.PublicKey.(*ecdsa.PublicKey)

	// настройка mTLS
	//загрузка пары ключей для прокси для mTLS
	clientCert, err := tls.LoadX509KeyPair(cfg.Certificates.ProxyCertFile, cfg.Certificates.ProxyKeyFile)
	if err != nil {
		return err
	}
	//загрузка CA cert
	caPEM, err := os.ReadFile(cfg.Certificates.CACertFile)
	if err != nil {
		return err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	//создаем конфиг для подключения по mTLS с хранилищем
	tlsClientCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}
	tr := &http.Transport{TLSClientConfig: tlsClientCfg}
	httpClient := &http.Client{Transport: tr}

	signer := &RemoteSigner{
		publicKey: pubKey,
		client:    httpClient,
		signURL:   fmt.Sprintf("https://%s/sign", cfg.Servers.KeyServerAddr),
	}

	//сертификат, в котором вместо приватного ключа реализация интерфейса
	tlsCert := tls.Certificate{
		Certificate: [][]byte{block.Bytes},
		PrivateKey:  signer,
		Leaf:        webCert,
	}

	//конфиг TLS для входящих соединений
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	backendURL, _ := url.Parse("http://" + cfg.Servers.HTTPServerAddr)
	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request from %s: %s", r.RemoteAddr, r.URL.String())
		proxy.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:      cfg.Servers.ProxyAddr,
		TLSConfig: tlsCfg,
		Handler:   handler,
	}
	return server.ListenAndServeTLS("", "")
}
