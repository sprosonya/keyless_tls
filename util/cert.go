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
	"time"
)

func GenerateCerts(cfg *config.Config) error {
	if err := os.MkdirAll(cfg.Certificates.Directory, 0755); err != nil {
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
	saveCert(cfg.Certificates.CACertFile, caDER)
	savePrivateKey(cfg.Certificates.CAKeyFile, caKey)

	// keyserver cert
	ksKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ip, _, err := net.SplitHostPort(cfg.Servers.KeyServerAddr)
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
		IPAddresses: []net.IP{net.ParseIP(ip)},
		DNSNames:    []string{"localhost"},
	}
	ksDER, err := x509.CreateCertificate(rand.Reader, ksTemplate, caTemplate, &ksKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	saveCert(cfg.Certificates.KeyServerCertFile, ksDER)
	savePrivateKey(cfg.Certificates.KeyServerKeyFile, ksKey)

	// proxy cert
	ip, _, err = net.SplitHostPort(cfg.Servers.ProxyAddr)
	if err != nil {
		return err
	}
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
		IPAddresses: []net.IP{net.ParseIP(ip)},
	}
	pxDER, err := x509.CreateCertificate(rand.Reader, pxTemplate, caTemplate, &pxKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	saveCert(cfg.Certificates.ProxyCertFile, pxDER)
	savePrivateKey(cfg.Certificates.ProxyKeyFile, pxKey)

	// web server cert
	ip, _, err = net.SplitHostPort(cfg.Servers.HTTPServerAddr)
	if err != nil {
		return err
	}
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
		IPAddresses: []net.IP{net.ParseIP(ip)},
		DNSNames:    []string{"localhost"},
	}
	webDER, err := x509.CreateCertificate(rand.Reader, webTemplate, caTemplate, &webKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	saveCert(cfg.Certificates.WebCertFile, webDER)
	savePrivateKey(cfg.Certificates.WebKeyFile, webKey)

	return nil
}

func saveCert(path string, der []byte) {
	certOut, _ := os.Create(path)
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func savePrivateKey(path string, key *ecdsa.PrivateKey) error {
	keyOut, err := os.Create(path)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
