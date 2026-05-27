package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"keyless/config"
	"math/big"
	"net"
	"os"
	"time"
)

func GenerateCerts(cfg *config.Config, webCertKey bool) error {
	if err := os.MkdirAll(cfg.Certificates.Directory, 0755); err != nil {
		return fmt.Errorf("creating cert directory: %w", err)
	}

	// CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
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
		return fmt.Errorf("creating CA certificate: %w", err)
	}
	if err := saveCert(cfg.Certificates.CACertFile, caDER); err != nil {
		return fmt.Errorf("saving CA certificate: %w", err)
	}
	if err := savePrivateKey(cfg.Certificates.CAKeyFile, caKey); err != nil {
		return fmt.Errorf("saving CA key: %w", err)
	}

	// keyserver cert
	ksKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating keyserver key: %w", err)
	}
	ip, _, err := net.SplitHostPort(cfg.Servers.SignServerAddr)
	if err != nil {
		return fmt.Errorf("parsing keyserver address: %w", err)
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
		return fmt.Errorf("creating keyserver certificate: %w", err)
	}
	if err := saveCert(cfg.Certificates.SignServerCertFile, ksDER); err != nil {
		return fmt.Errorf("saving keyserver certificate: %w", err)
	}
	if err := savePrivateKey(cfg.Certificates.SignServerKeyFile, ksKey); err != nil {
		return fmt.Errorf("saving keyserver key: %w", err)
	}

	// proxy cert
	ip, _, err = net.SplitHostPort(cfg.Servers.ProxyAddr)
	if err != nil {
		return fmt.Errorf("parsing proxy address: %w", err)
	}
	pxKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating proxy key: %w", err)
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
		return fmt.Errorf("creating proxy certificate: %w", err)
	}
	if err := saveCert(cfg.Certificates.ProxyCertFile, pxDER); err != nil {
		return fmt.Errorf("saving proxy certificate: %w", err)
	}
	if err := savePrivateKey(cfg.Certificates.ProxyKeyFile, pxKey); err != nil {
		return fmt.Errorf("saving proxy key: %w", err)
	}

	// web server cert
	if !webCertKey {
		ip, _, err = net.SplitHostPort(cfg.Servers.HTTPServerAddr)
		if err != nil {
			return fmt.Errorf("parsing httpserver address: %w", err)
		}
		webKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generating web key: %w", err)
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
			return fmt.Errorf("creating web certificate: %w", err)
		}
		if err := saveCert(cfg.Certificates.WebCertFile, webDER); err != nil {
			return fmt.Errorf("saving web certificate: %w", err)
		}
		if err := savePrivateKey(cfg.Certificates.WebKeyFile, webKey); err != nil {
			return fmt.Errorf("saving web key: %w", err)
		}
	}
	return nil
}

func saveCert(path string, der []byte) error {
	certOut, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating cert file %s: %w", path, err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return fmt.Errorf("encoding cert %s: %w", path, err)
	}
	return nil
}

func savePrivateKey(path string, key *ecdsa.PrivateKey) error {
	keyOut, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating key file %s: %w", path, err)
	}
	defer keyOut.Close()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling key for %s: %w", path, err)
	}
	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
