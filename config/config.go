package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	Proxy struct {
		ListenAddr    string `json:"listen_addr"`
		BackendAddr   string `json:"backend_addr"`
		KeyServerAddr string `json:"keyserver_addr"`
		WebCertFile   string `json:"web_cert_file"`
		MTLSCertFile  string `json:"mtls_cert_file"`
		MTLSKeyFile   string `json:"mtls_key_file"`
		CACertFile    string `json:"ca_cert_file"`
	} `json:"proxy"`
	KeyServer struct {
		ListenAddr        string `json:"listen_addr"`
		ServerCertFile    string `json:"server_cert_file"`
		ServerKeyFile     string `json:"server_key_file"`
		CACertFile        string `json:"ca_cert_file"`
		WebPrivateKeyFile string `json:"web_private_key_file"`
	} `json:"keyserver"`
	HTTPServer struct {
		ListenAddr string `json:"listen_addr"`
	} `json:"httpserver"`
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
