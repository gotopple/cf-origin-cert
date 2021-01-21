package agent

import (
	"io/ioutil"
	"log"
)

type FilesystemCertificateWriter struct {
	certOutputPath string
	keyOutputPath  string
	lastID         string
}

func NewFilesystemCertificateWriter(certOutputPath string, keyOutputPath string) CertificateWriter {
	return &FilesystemCertificateWriter{
		certOutputPath: certOutputPath,
		keyOutputPath:  keyOutputPath,
	}
}

func (w *FilesystemCertificateWriter) Write(certKeyPair *CertKeyPair) {
	if certKeyPair.ID == w.lastID {
		return
	}
	w.lastID = certKeyPair.ID

	err := ioutil.WriteFile(w.certOutputPath, certKeyPair.CertPEM, 0600)
	if err != nil {
		log.Printf("unable to write certificate file: %x", err)
	}

	err = ioutil.WriteFile(w.keyOutputPath, certKeyPair.Key, 0600)
	if err != nil {
		log.Printf("unable to write key file: %x", err)
	}
}
