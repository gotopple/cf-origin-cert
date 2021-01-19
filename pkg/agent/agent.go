package agent

import (
	"bytes"
	"context"
	"fmt"
	"github.com/gotopple/cf-origin-cert/pkg/observer"
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
	*observer.Observable
	writer    CertificateWriter
	apiKey    string
	period    time.Duration
	validity  int
	api       *cloudflare.API
	generator CSRGenerator
	cache     []CertKeyPair
}

func NewCertAgent(apiKey string, period time.Duration, validity int, writer CertificateWriter) (*CertAgent, error) {
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
	agent := &CertAgent{
		Observable: observer.MakeObservable(),
		writer:     writer,
		apiKey:     apiKey,
		period:     period,
		validity:   validity,
		api:        api,
		generator:  generator,
		cache:      []CertKeyPair{},
	}

	return agent, nil
}

func (a *CertAgent) Run(ctx context.Context, domain string) {
	a.Lock()
	defer a.Unlock()
	subject := fmt.Sprintf("*.%s", domain)
	dnsNames := []string{domain, subject}

	generateAndWrite := func() *CertKeyPair {
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

		result := CertKeyPair{ID: cert.ID, CertPEM: []byte(cert.Certificate), Key: key}
		a.writer.Write(&result)

		// prepend to cache
		a.cache = append([]CertKeyPair{result}, a.cache...)

		return &result
	}

	cleanup := func(all bool) {
		// It does not make any sense to list all of the known certificates (at Cloudflare)
		// and prune the old ones. The local agent can only clean up the certs that it knows
		// about since there may be other agents running.
		if all || len(a.cache) > 1 {
			var wg sync.WaitGroup
			for i, v := range a.cache {
				if !all && i == 0 {
					continue
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := a.api.RevokeOriginCertificate(v.ID)
					if err != nil {
						// Not bugsnag, but some other visibility or reporting
						log.Printf("unable to revoke origin certificate id#%s: %v", err)
					}
				}()
			}
			if !all {
				a.cache = []CertKeyPair{a.cache[0]}
			} else {
				a.cache = []CertKeyPair{}
			}
			wg.Wait()
		}
	}

	initialCert := generateAndWrite()
	a.Notify(initialCert)

	for {
		select {
		case <-time.After(a.period):
			newCert := generateAndWrite()
			cleanup(false)

			a.Notify(newCert)
		case <-ctx.Done():
			cleanup(true)
			return
		}
	}
}

func (a *CertAgent) GetCertKeyPair(backoff int) (CertKeyPair, error) {
	if len(a.cache) <= backoff {
		return CertKeyPair{}, fmt.Errorf(`no more credentials`)
	}
	return a.cache[backoff], nil
}
