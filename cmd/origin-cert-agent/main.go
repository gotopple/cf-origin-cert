package main

import (
	"context"
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
		cli.StringFlag{
			Name:   "post-hook, ph",
			Usage:  "Post hook",
			Value:  "",
			EnvVar: "CF_ORIGIN_POST_HOOK",
		},
	}
	app.Action = Start

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func Start(c *cli.Context) {
	if len(c.String(`origin-api-key`)) <= 0 {
		log.Fatal("origin-api-key is a required parameter")
	}
	if len(c.String(`domain`)) <= 0 {
		log.Fatal("domain is a required parameter")
	}
	switch c.Int(`ttl`) {
	case agent.Week:
	case agent.Month:
	case agent.Quarter:
	default:
		log.Fatal(`invalid value for ttl [7, 30, 90] days`)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt)

	ca, err := agent.NewCertAgent(
		c.String(`origin-api-key`),
		c.Duration(`rotation-frequency`),
		c.Int(`ttl`),
		agent.NewFilesystemCertificateWriter(c.String("certout"), c.String("keyout")),
	)
	if err != nil {
		log.Fatal(err)
	}

	postHook := c.String("post-hook")
	if postHook != "" {
		ca.Attach(agent.NewPostHookObserver(postHook))
	}

	ctx, cancel := context.WithCancel(context.Background())
	go ca.Run(ctx, c.String(`domain`))

	<-sigchan

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
	cancel()
	time.Sleep(ShortTick)
	os.Exit(127)
}
