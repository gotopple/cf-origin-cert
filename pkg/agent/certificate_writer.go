package agent

type CertificateWriter interface {
	Write(certKeyPair *CertKeyPair)
}
