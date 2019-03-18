package agent

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/allingeek/cloudflare-go"
)

const (
	Week    = 7
	Month   = 30
	Quarter = 90
)

type CertKeyPair struct {
	ID      string
	CertPEM []byte
	Key     []byte
}
type CertAgent struct {
	sync.Mutex
	apiKey    string
	period    time.Duration
	validity  int
	api       *cloudflare.API
	generator CSRGenerator
	cache     []CertKeyPair
}

func NewCertAgent(apiKey string, period time.Duration, validity int) (*CertAgent, error) {
	switch validity {
	case Week:
	case Month:
	case Quarter:
	default:
		return nil, fmt.Errorf(`invalid value for validity [7, 30, 90]`)
	}
	var err error
	var api *cloudflare.API
	var logger = log.New(os.Stdout, "", log.LstdFlags)
	if api, err = cloudflare.NewWithUserServiceKey(apiKey, cloudflare.UsingLogger(logger)); err != nil {
		return nil, err
	}

	generator := SHA256RSAGenerator{}
	return &CertAgent{
		apiKey:    apiKey,
		period:    period,
		validity:  validity,
		api:       api,
		generator: generator,
		cache:     []CertKeyPair{},
	}, nil
}

func (a *CertAgent) Run(ctx context.Context, domain string) {
	a.Lock()
	defer a.Unlock()
	subject := fmt.Sprintf("*.%s", domain)
	dnsNames := []string{domain, subject}

	generate := func() {
		key, pem, err := a.generator.GenerateNewPEM(subject, dnsNames)
		if err != nil {
			log.Fatal(err)
		}
		// encode all possible newline characters as "\n"
		npem := bytes.Replace(pem, []byte{13, 10}, []byte{10}, -1)
		npem = bytes.Replace(npem, []byte{13}, []byte{10}, -1)
		cert, err := a.api.CreateOriginCertificate(cloudflare.OriginCACertificate{
			Hostnames:       dnsNames,
			RequestValidity: 30,
			RequestType:     `origin-rsa`,
			CSR:             string(pem),
		})
		if err != nil {
			log.Fatal(err)
		}

		// prepend to cache
		a.cache = append([]CertKeyPair{CertKeyPair{ID: cert.ID, CertPEM: []byte(cert.Certificate), Key: key}}, a.cache...)
	}

	cleanup := func() {
		// It does not make any sense to list all of the known certificates (at Cloudflare)
		// and prune the old ones. The local agent can only clean up the certs that it knows
		// about since there may be other agents running.
		if len(a.cache) > 1 {
			for i, v := range a.cache {
				if i == 0 {
					continue
				}
				_, err := a.api.RevokeOriginCertificate(v.ID)
				if err != nil {
					// Not bugsnag, but some other visibility or reporting
					log.Printf("unable to revoke origin certificate id#%s: %v", err)
				}
			}
			a.cache = []CertKeyPair{a.cache[0]}
		}
	}

	generate()
	for {
		select {
		case <-time.After(a.period):
			generate()
			cleanup()
		case <-ctx.Done():
			for _, v := range a.cache {
				_, _ = a.api.RevokeOriginCertificate(v.ID)
			}
			break
		}
	}
}

func (a *CertAgent) GetCertKeyPair(backoff int) (CertKeyPair, error) {
	if len(a.cache) <= backoff {
		return CertKeyPair{}, fmt.Errorf(`no more credentials`)
	}
	return a.cache[backoff], nil
}
