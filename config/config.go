package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Servers      ServersConfig      `json:"servers"`
	Certificates CertificatesConfig `json:"certificates"`
}

type ServersConfig struct {
	ProxyAddr      string `json:"proxy_addr"`
	SignServerAddr string `json:"signserver_addr"`
	HTTPServerAddr string `json:"httpserver_addr"`
}

type CertificatesConfig struct {
	Directory           string `json:"directory"`
	WebCertFile         string `json:"web_cert_file"`
	WebKeyFile          string `json:"web_key_file"`
	WebEncryptedKeyFile string `json:"web_encrypted_key_file"`
	ProxyCertFile       string `json:"proxy_cert_file"`
	ProxyKeyFile        string `json:"proxy_key_file"`
	CACertFile          string `json:"ca_cert_file"`
	CAKeyFile           string `json:"ca_key_file"`
	SignServerCertFile  string `json:"signserver_cert_file"`
	SignServerKeyFile   string `json:"signserver_key_file"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading file: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parsing json: %w", err)
	}
	return cfg, nil
}
