# cf-origin-cert

## Install the Agent

```
git clone git@github.com:gotopple/cf-origin-cert.git
cd cf-origin-cert/cmd/origin-cert-agent
go build
ls -al ./origin-cert-agent
```

## Agent Help

```
NAME:
   origin-cert-agent - dynamic origin certificate management

USAGE:
   origin-cert-agent [global options] command [command options] [arguments...]

VERSION:
   0.0.0

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --origin-api-key value, -p value      An "Origin CA Key" [$CF_ORIGIN_API_KEY]
   --rotation-frequency value, -f value  Origin certificate rotation frequency (default: 168h0m0s) [$CF_ORIGIN_ROTATION_FREQUENCY]
   --ttl value, -l value                 Requested certificate TTL (default: 30) [$CF_ORIGIN_CERT_TTL]
   --domain value, -n value              The tld [$CF_ORIGIN_TLD]
   --certout value, -c value             Certificate output file name (default: "./cert.pem") [$CF_ORIGIN_CERT_OUT_FILE]
   --keyout value, -k value              Private key output file name (default: "./key.pem") [$CF_ORIGIN_KEY_OUT_FILE]
   --help, -h                            show help
   --version, -v                         print the version
```
