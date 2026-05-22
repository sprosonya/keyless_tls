package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"keyless/config"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func GenerateCerts(cfg *config.Config) error {
	dir := filepath.Dir(cfg.Proxy.CACertFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	saveCert(cfg.Proxy.CACertFile, caDER)
	saveECKey(cfg.Proxy.CACertFile[:len(cfg.Proxy.CACertFile)-4]+".key", caKey)

	// keyserver cert
	ksKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ksTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"KeyServer"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}
	ksDER, err := x509.CreateCertificate(rand.Reader, ksTemplate, caTemplate, &ksKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	saveCert(cfg.KeyServer.ServerCertFile, ksDER)
	saveECKey(cfg.KeyServer.ServerKeyFile, ksKey)

	// proxy cert
	pxKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pxTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Proxy"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	pxDER, err := x509.CreateCertificate(rand.Reader, pxTemplate, caTemplate, &pxKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	saveCert(cfg.Proxy.MTLSCertFile, pxDER)
	saveECKey(cfg.Proxy.MTLSKeyFile, pxKey)

	// web server cert
	webKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	webTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			Organization: []string{"WebServer"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}
	webDER, err := x509.CreateCertificate(rand.Reader, webTemplate, caTemplate, &webKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	saveCert(cfg.Proxy.WebCertFile, webDER)
	saveECKey(cfg.KeyServer.WebPrivateKeyFile, webKey)

	return nil
}

func saveCert(path string, der []byte) {
	certOut, _ := os.Create(path)
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func saveECKey(path string, key *ecdsa.PrivateKey) {
	keyOut, _ := os.Create(path)
	defer keyOut.Close()
	b, _ := x509.MarshalECPrivateKey(key)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}
