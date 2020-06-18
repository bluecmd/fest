# Front-End for easy Secure Transport (FEST)

FEST, which also happens to mean Party or Feast in Swedish, is
a proxy that lives on the edge of a network providing easy TLS management,
as well as secure user management.

It is meant to be a opinionated proxy to make it easy to put service interfaces
directly on the Internet, removing the need to use VPNs.

## TLS

TLS will be implemented using Let's Encrypt.

## User Authentication

User authentication will be implemented using Google, Github, and U2F.
A user can be configured to be authenticated using any one of the ones
mentioned.

## Daemon Authentication

Daemons or API clients will be authenticated using mutual TLS authentication
which will optionally be passed onto the backend as re-generated certificates.

This means that even browser connections using conventional OAuth or similar
will look like normal mTLS connections on the backend.

## Authorization

Authorization rules will be statically configured configuration files using
Protobufs. Live reload of configuration will be supported.

## Logs

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
