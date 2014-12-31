package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

var cipherSuitesMap = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
}

func ParseCipherSuiteLietrals(literals []string) ([]uint16, error) {
	var has bool
	nsymbol := len(literals)
	if nsymbol == 0 {
		return nil, nil
	}
	symbol := make([]uint16, nsymbol)
	for i, literal := range literals {
		symbol[i], has = cipherSuitesMap[literal]
		if !has {
			return nil, fmt.Errorf("invalided cipher suite: %s", literal)
		}
	}
	return symbol, nil
}

// TLSInfo holds the SSL certificates paths.
type TLSInfo struct {
	CertFile     string `json:"CertFile"`
	KeyFile      string `json:"KeyFile"`
	CAFile       string `json:"CAFile"`
	CipherSuites []string
}

func (info TLSInfo) Scheme() string {
	if info.KeyFile != "" && info.CertFile != "" {
		return "https"
	} else {
		return "http"
	}
}

// Generates a tls.Config object for a server from the given files.
func (info TLSInfo) ServerConfig() (*tls.Config, error) {
	// Both the key and cert must be present.
	if info.KeyFile == "" || info.CertFile == "" {
		return nil, fmt.Errorf("KeyFile and CertFile must both be present[key: %v, cert: %v]", info.KeyFile, info.CertFile)
	}

	var cfg tls.Config

	tlsCert, err := tls.LoadX509KeyPair(info.CertFile, info.KeyFile)
	if err != nil {
		return nil, err
	}

	cfg.Certificates = []tls.Certificate{tlsCert}

	if info.CAFile != "" {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cp, err := newCertPool(info.CAFile)
		if err != nil {
			return nil, err
		}

		cfg.RootCAs = cp
		cfg.ClientCAs = cp
	} else {
		cfg.ClientAuth = tls.NoClientCert
	}

	cipherSuites, err := ParseCipherSuiteLietrals(info.CipherSuites)
	if err != nil {
		return nil, err
	}
	cfg.CipherSuites = cipherSuites

	return &cfg, nil
}

// Generates a tls.Config object for a client from the given files.
func (info TLSInfo) ClientConfig() (*tls.Config, error) {
	var cfg tls.Config

	if info.KeyFile == "" || info.CertFile == "" {
		return &cfg, nil
	}

	tlsCert, err := tls.LoadX509KeyPair(info.CertFile, info.KeyFile)
	if err != nil {
		return nil, err
	}

	cfg.Certificates = []tls.Certificate{tlsCert}

	if info.CAFile != "" {
		cp, err := newCertPool(info.CAFile)
		if err != nil {
			return nil, err
		}

		cfg.RootCAs = cp
	}

	cipherSuites, err := ParseCipherSuiteLietrals(info.CipherSuites)
	if err != nil {
		return nil, err
	}
	cfg.CipherSuites = cipherSuites

	return &cfg, nil
}

// newCertPool creates x509 certPool with provided CA file
func newCertPool(CAFile string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	pemByte, err := ioutil.ReadFile(CAFile)
	if err != nil {
		return nil, err
	}

	for {
		var block *pem.Block
		block, pemByte = pem.Decode(pemByte)
		if block == nil {
			return certPool, nil
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certPool.AddCert(cert)
	}

}
