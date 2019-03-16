package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/gotopple/cf-origin-cert/pkg/agent"
	"github.com/urfave/cli"
)

var (
	ShortTick  = 5 * time.Second
	LongTick   = 10 * time.Second
	HalfMinute = 30 * time.Second
	Week       = 24 * 7 * time.Hour
)

func main() {
	app := cli.NewApp()
	app.Name = "origin-cert-agent"
	app.Usage = "dynamic origin certificate management"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "origin-api-key, p",
			Usage:  `An "Origin CA Key"`,
			EnvVar: "CF_ORIGIN_API_KEY",
		},
		cli.DurationFlag{
			Name:   "rotation-frequency, f",
			Usage:  `Origin certificate rotation frequency`,
			Value:  Week,
			EnvVar: "CF_ORIGIN_ROTATION_FREQUENCY",
		},
		cli.IntFlag{
			Name:   "ttl, l",
			Usage:  "Requested certificate TTL",
			Value:  agent.Month,
			EnvVar: "CF_ORIGIN_CERT_TTL",
		},
		cli.StringFlag{
			Name:   "domain, n",
			Usage:  "The tld",
			EnvVar: "CF_ORIGIN_TLD",
		},
		cli.StringFlag{
			Name:   "certout, c",
			Usage:  `Certificate output file name`,
			Value:  `./cert.pem`,
			EnvVar: "CF_ORIGIN_CERT_OUT_FILE",
		},
		cli.StringFlag{
			Name:   "keyout, k",
			Usage:  `Private key output file name`,
			Value:  `./key.pem`,
			EnvVar: "CF_ORIGIN_KEY_OUT_FILE",
		},
	}
	app.Action = Start

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func Start(c *cli.Context) error {
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt)

	ca, err := agent.NewCertAgent(c.String(`origin-api-key`), c.Duration(`rotation-frequency`), c.Int(`ttl`))
	if err != nil {
		log.Fatal(err)
	}
	stopper := make(chan struct{})
	go ca.Run(c.String(`domain`), stopper)
	var lastID string
	for {
		select {
		case <-time.After(5 * time.Second):
			creds, err := ca.GetCertKeyPair(0)
			if creds.ID == lastID {
				continue
			}
			lastID = creds.ID
			if err != nil {
				log.Print(err)
				continue
			}
			err = ioutil.WriteFile(c.String(`certout`), creds.CertPEM, 0600)
			if err != nil {
				log.Printf("unable to write certificate file: %x", err)
			}
			err = ioutil.WriteFile(c.String(`keyout`), creds.Key, 0600)
			if err != nil {
				log.Printf("unable to write key file: %x", err)
			}

		case <-sigchan:
			err = os.Remove(c.String(`certout`))
			if err != nil {
				// bugsnag report?
				log.Printf("unable to clean up revoked certificate file: %x", err)
			}
			err = os.Remove(c.String(`keyout`))
			if err != nil {
				// bugsnag report?
				log.Printf("unable to clean up key file for revoked: %x", err)
			}
			close(stopper)
			time.Sleep(ShortTick)
			os.Exit(127)
		}
	}
}
