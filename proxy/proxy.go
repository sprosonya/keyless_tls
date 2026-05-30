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
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

type RemoteSigner struct {
	publicKey *ecdsa.PublicKey
	client    *http.Client
	signURL   string
}

func (rs *RemoteSigner) Public() crypto.PublicKey {
	return rs.publicKey
}

type SignRequest struct {
	Digest string `json:"digest"`
}
type SignResponse struct {
	Signature string `json:"signature"`
}

func (rs *RemoteSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	req := SignRequest{
		Digest: base64.RawStdEncoding.EncodeToString(digest),
	}
	data, _ := json.Marshal(req)
	log.Println("Send sign request. Digest:", req.Digest)

	resp, err := rs.client.Post(rs.signURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("posting sign request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("signserver error: %s, body: %s", resp.Status, string(body))
	}

	reply := SignResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, fmt.Errorf("decoding sign response: %w", err)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("draining response body: %w", err)
	}

	sig, err := base64.RawStdEncoding.DecodeString(reply.Signature)
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	return sig, nil
}

// StartProxy запускает TLS-прокси. Все настройки передаются через параметры.
func StartProxy(proxyAddr, backendAddr, signServerAddr, webCertFile, proxyCertFile, proxyKeyFile, caCertFile string) error {
	webCertPEM, err := os.ReadFile(webCertFile)
	if err != nil {
		return fmt.Errorf("reading web cert file: %w", err)
	}

	var certDER [][]byte
	var leaf *x509.Certificate
	rest := webCertPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certDER = append(certDER, block.Bytes)
		if leaf == nil {
			leaf, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("parsing leaf certificate: %w", err)
			}
		}
	}
	if len(certDER) == 0 {
		return fmt.Errorf("no certificates found in %s", webCertFile)
	}
	pubKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("web certificate public key is not ECDSA")
	}

	clientCert, err := tls.LoadX509KeyPair(proxyCertFile, proxyKeyFile)
	if err != nil {
		return fmt.Errorf("loading mTLS client cert: %w", err)
	}

	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	keyLogFile, err := os.OpenFile("proxy_mtls.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("opening keylog file: %w", err)
	}
	defer keyLogFile.Close()

	tlsClientCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
		KeyLogWriter: keyLogFile,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsClientCfg,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
	}
	httpClient := &http.Client{Transport: transport}

	signer := &RemoteSigner{
		publicKey: pubKey,
		client:    httpClient,
		signURL:   fmt.Sprintf("https://%s/sign", signServerAddr),
	}

	tlsCert := tls.Certificate{
		Certificate: certDER,
		PrivateKey:  signer,
		Leaf:        leaf,
	}

	incomingKeyLogFile, err := os.OpenFile("proxy_incoming.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("opening incoming keylog file: %w", err)
	}
	defer incomingKeyLogFile.Close()

	incomingTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		KeyLogWriter: incomingKeyLogFile,
	}

	backendURL, err := url.Parse("http://" + backendAddr)
	if err != nil {
		return fmt.Errorf("invalid backend URL: %w", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		log.Printf("Incoming request from %s: %s %s", ip, r.Method, r.URL.String())
		proxy.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:      proxyAddr,
		TLSConfig: incomingTLSConfig,
		Handler:   loggingHandler,
	}

	log.Printf("Starting TLS proxy on %s", proxyAddr)
	return server.ListenAndServeTLS("", "")
}
