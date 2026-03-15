package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

type CertCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
}

func NewCertCache(ca *x509.Certificate, caKey *ecdsa.PrivateKey) *CertCache {
	return &CertCache{
		certs: make(map[string]*tls.Certificate),
		ca:    ca,
		caKey: caKey,
	}
}

func (cc *CertCache) GetCertificate(host string) (*tls.Certificate, error) {
	// Strip port if present
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}

	cc.mu.RLock()
	cert, ok := cc.certs[h]
	cc.mu.RUnlock()
	if ok {
		return cert, nil
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Double-check after acquiring write lock
	if cert, ok := cc.certs[h]; ok {
		return cert, nil
	}

	cert, err = generateHostCert(h, cc.ca, cc.caKey)
	if err != nil {
		return nil, err
	}
	cc.certs[h] = cert
	return cert, nil
}

func generateHostCert(host string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return tlsCert, nil
}

func LoadOrCreateCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Try to load existing CA
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	if certErr == nil && keyErr == nil {
		return parseCA(certPEM, keyPEM)
	}

	// Generate new CA
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "SOCKS5 Proxy CA", Organization: []string{"socks5proxy"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA cert: %w", err)
	}

	// Write cert
	certOut, err := os.Create(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("write CA cert: %w", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	// Write key
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA key: %w", err)
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("write CA key: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyOut.Close()

	ca, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return ca, key, nil
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}

	return ca, key, nil
}
