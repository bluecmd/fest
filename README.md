# Front-End for easy Secure Transport (FEST)

***Deprecated***. This was a fun experiment but in the end the amount of corner-cases
both in terms of protocol but also implementation of frontends this is too big
for me to continue working on. I will personally be switching to using
[Pomerium](https://www.pomerium.io/docs/) and
[prodaccess](https://github.com/dhtech/prodaccess).

FEST, which also happens to mean Party or Feast in Swedish, is
a proxy that lives on the edge of a network providing easy TLS management,
as well as secure user management.

It is meant to be a opinionated proxy to make it easy to put service interfaces
directly on the Internet, removing the need to use VPNs.

## Features

Currently supported:

 * :heavy_check_mark: RFC 8555 ACME / Let's Encrypt integration
 * :heavy_check_mark: Support being behind DDoS protection
 * :heavy_check_mark: HTTP/2 support
 * :heavy_check_mark: Github OAuth2 support 
 * :heavy_check_mark: Prometheus metrics
 * :heavy_check_mark: Credentials forwarding (SSO)

 Planned: 
 
 * :x: U2F authentication
 * :x: Google OAuth2 support
 * :x: Backend plugins to allow for things like
   * :x: Remote Desktop Protocol (RDP) via RD Gateway
   * :x: VMware Remote Console (the stand-alone client) pass-through
 
## Usage

FEST is configured using two madatory sources: command line flags and
configuration file. The flags are meant to be fire-and-forget, while the
configuration file is expected to change and be hot reloadable.

See [config.textpb.default](config.textpb.default) for an example service
configuration.

Example startup of FEST:

```
/usr/local/bin/fest \
  --acme_directory="https://acme-v02.api.letsencrypt.org/directory" \
  --acme_terms="https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf" \
  --acme_contact="mailto:fest@example.com" \
  --auth_domain="fest.example.com"
```

This configures FEST to use `fest.example.com` as the base domain for things
like OAuth2 callbacks. The `auth_domain` should not be present in the service
configuration file.

## Design

FEST is intended to be an opinionated server software, focusing on making
it easy for hobbists and small organizations to not need to use VPNs to access
internal services. The commercial options such as Cloudflare Access can be
too expensive or limited for individual use.

### TLS Certificate Management

TLS certificate management is implemeted using RFC 8555 ACME protocol.
This allows usage of e.g. Lets Encrypt automatic certificate management.

### User Authentication

User authentication will be implemented using Google, Github, and U2F.
A user can be configured to be authenticated using any one of the ones
mentioned.

### Daemon Authentication

Daemons or API clients will be authenticated using mutual TLS authentication
which will optionally be passed onto the backend as re-generated certificates.

This means that even browser connections using conventional OAuth or similar
will look like normal mTLS connections on the backend.

### Authorization

Authorization rules will be statically configured configuration files using
Protobufs. Live reload of configuration will be supported.

### Logs

Flow logs of traffic will be outputted to the console as well as auditing data
about the authentication and authorization decisions done. No logging of traffic
forwarded will be implemented.

## Protobuf definitions

When updating the .proto file, make sure to update and commit the updated Go
implementation. The reason for this is to make it trivial to include the
definitions without having to do a pre-build step in Go.

1. Make sure you have `protoc` installed. On Debian this can be installed via
   `apt install protobuf-compiler`.

2. Install `protoc-gen-go` by running
   `go get -u github.com/golang/protobuf/protoc-gen-go`.

3. Run `make -C proto` to update the .pb.go file(s).

## Usage with DDoS protection

FEST is tested to run fine behind Cloudflare as DDoS protection. Cloudflare
does not support HTTP/2 or pure TLS connections, at least in the free tier,
but other than things should Just Work (TM).

## Tests?

Paraphrasing a world leader:

> If you test, you find bugs. If you don't test, no bugs.

Serious answer: Right now, none - I wanted to focus my time on getting
something to work first. Things will need to be refactored anyway,
which likely will be given tests at that point.
