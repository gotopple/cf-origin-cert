package agent

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

type CSRGenerator interface {
	GenerateNewPEM(subject string, dnsNames []string) (key, csr []byte, err error)
}

type SHA256RSAGenerator struct{}

func (g SHA256RSAGenerator) GenerateNewPEM(subject string, dnsNames []string) (key, csr []byte, err error) {
	var certKey *rsa.PrivateKey
	if certKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: subject},
		DNSNames: dnsNames,

		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
	}

	var csrDER []byte
	if csrDER, err = x509.CreateCertificateRequest(rand.Reader, template, certKey); err != nil {
		return
	}

	key = pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
		Type:  `RSA PRIVATE KEY`})

	csr = pem.EncodeToMemory(&pem.Block{
		Bytes: csrDER,
		Type:  `CERTIFICATE REQUEST`})
	return
}
