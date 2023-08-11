package openldap_exporter

// Code from https://github.com/influxdata/telegraf/blob/master/plugins/common/tls/config.go

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/youmark/pkcs8"
)

const TLSMinVersionDefault = tls.VersionTLS12

// ClientConfig represents the standard client TLS config.
type ClientConfig struct {
	TLSCA               string
	TLSCert             string
	TLSKey              string
	TLSKeyPwd           string
	InsecureSkipVerify  bool
	ServerName          string
	RenegotiationMethod string
}

func (c *ClientConfig) TLSConfig() (*tls.Config, error) {
	var renegotiationMethod tls.RenegotiationSupport
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
		Renegotiation:      renegotiationMethod,
	}

	if c.TLSCA != "" {
		pool, err := makeCertPool([]string{c.TLSCA})
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}

	if c.TLSCert != "" && c.TLSKey != "" {
		err := loadCertificate(tlsConfig, c.TLSCert, c.TLSKey, c.TLSKeyPwd)
		if err != nil {
			return nil, err
		}
	}

	// Explicitly and consistently set the minimal accepted version using the
	// defined default. We use this setting for both clients and servers
	// instead of relying on Golang's default that is different for clients
	// and servers and might change over time.
	tlsConfig.MinVersion = TLSMinVersionDefault

	tlsConfig.ServerName = c.ServerName

	return tlsConfig, nil
}

func makeCertPool(certFiles []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, certFile := range certFiles {
		cert, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("could not read certificate %q: %w", certFile, err)
		}
		if !pool.AppendCertsFromPEM(cert) {
			return nil, fmt.Errorf("could not parse any PEM certificates %q: %w", certFile, err)
		}
	}
	return pool, nil
}

func loadCertificate(config *tls.Config, certFile, keyFile, privateKeyPassphrase string) error {
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("could not load certificate %q: %w", certFile, err)
	}

	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("could not load private key %q: %w", keyFile, err)
	}

	keyPEMBlock, _ := pem.Decode(keyBytes)
	if keyPEMBlock == nil {
		return errors.New("failed to decode private key: no PEM data found")
	}

	var cert tls.Certificate
	if keyPEMBlock.Type == "ENCRYPTED PRIVATE KEY" {
		if privateKeyPassphrase == "" {
			return errors.New("missing password for PKCS#8 encrypted private key")
		}
		var decryptedKey *rsa.PrivateKey
		decryptedKey, err = pkcs8.ParsePKCS8PrivateKeyRSA(keyPEMBlock.Bytes, []byte(privateKeyPassphrase))
		if err != nil {
			return fmt.Errorf("failed to parse encrypted PKCS#8 private key: %w", err)
		}
		cert, err = tls.X509KeyPair(certBytes, pem.EncodeToMemory(&pem.Block{Type: keyPEMBlock.Type, Bytes: x509.MarshalPKCS1PrivateKey(decryptedKey)}))
		if err != nil {
			return fmt.Errorf("failed to load cert/key pair: %w", err)
		}
	} else if keyPEMBlock.Headers["Proc-Type"] == "4,ENCRYPTED" {
		// The key is an encrypted private key with the DEK-Info header.
		// This is currently unsupported because of the deprecation of x509.IsEncryptedPEMBlock and x509.DecryptPEMBlock.
		return fmt.Errorf("password-protected keys in pkcs#1 format are not supported")
	} else {
		cert, err = tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return fmt.Errorf("failed to load cert/key pair: %w", err)
		}
	}
	config.Certificates = []tls.Certificate{cert}
	return nil
}
