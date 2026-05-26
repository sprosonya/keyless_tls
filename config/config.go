package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Servers      ServersConfig      `json:"servers"`
	Certificates CertificatesConfig `json:"certificates"`
}

type ServersConfig struct {
	ProxyAddr      string `json:"proxy_addr"`
	KeyServerAddr  string `json:"keyserver_addr"`
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
	KeyServerCertFile   string `json:"keyserver_cert_file"`
	KeyServerKeyFile    string `json:"keyserver_key_file"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
