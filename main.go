package main

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
)

type recordType uint8
type handshakeType uint8
type alertType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
)

const (
	handshakeClientHello handshakeType = 1
	handshakeCertificate handshakeType = 11
)

const (
	alertHandshakeFailure alertType = 40
	alertAccessDenied     alertType = 49
)

func httpHandler(c net.Conn) {
	defer c.Close()
	log.Printf("HTTP: %v", c)
}

func hsFail(t io.Writer, at alertType) {
	// Hardcoded Handshake failure TLS response
	// Transport Layer Security
	//     TLSv1.2 Record Layer: Alert (Level: Fatal, Description: Handshake Failure)
	//         Content Type: Alert (21)
	//         Version: TLS 1.2 (0x0303)
	//         Length: 2
	//         Alert Message
	//             Level: Fatal (2)
	//             Description: Handshake Failure (40)
	t.Write([]byte{byte(recordTypeAlert), 0x03, 0x03, 0, 2, 2, byte(at)})
}

type record struct {
	ct   recordType
	body []byte
}

func readRecord(r io.Reader) (*record, error) {
	var b [5]byte
	n, err := r.Read(b[:])
	if err != nil {
		return nil, fmt.Errorf("client: %v", err)
	}
	if n != len(b) {
		return nil, fmt.Errorf("client read too short (%d < %d)", n, len(b))
	}

	ct := recordType(b[0])
	ver := binary.BigEndian.Uint16(b[1:3])
	length := binary.BigEndian.Uint16(b[3:5])

	if ver < 0x0301 || ver > 0x0304 {
		return nil, fmt.Errorf("unsupported TLS handshake version, version=0x%04x", ver)
	}

	body := make([]byte, length)
	h := &record{ct: ct, body: body}

	n, err = r.Read(h.body)
	if err != nil {
		return nil, fmt.Errorf("client: %v", err)
	}
	if n != int(length) {
		return nil, fmt.Errorf("client read too short (%d < %d)", n, length)
	}

	return h, nil
}

type hsInfo struct {
	ht      handshakeType
	version uint16
	cert    [][]byte
}

func parseHandshake(body []byte) (*hsInfo, error) {
	i := &hsInfo{}
	i.ht = handshakeType(body[0])
	length := int(binary.BigEndian.Uint32(append([]byte{0}, body[1:4]...)))

	if len(body) < length {
		return nil, fmt.Errorf("handshake length incorrect: %d < %d", len(body), length)
	}

	if i.ht == handshakeClientHello {
		i.version = binary.BigEndian.Uint16(body[4:6])
	} else if i.ht == handshakeCertificate {
		clen := int(binary.BigEndian.Uint32(append([]byte{0}, body[4:7]...)))
		if len(body) < 7+clen {
			return nil, fmt.Errorf("certificates length incorrect: %d < %d", len(body), 7+clen)
		}
		cbody := body[7 : 7+clen]
		for {
			clen := int(binary.BigEndian.Uint32(append([]byte{0}, cbody[0:3]...)))
			if len(cbody) < 3+clen {
				return nil, fmt.Errorf("certificate length incorrect: %d < %d", len(cbody), 3+clen)
			}
			i.cert = append(i.cert, cbody[3:3+clen])
			cbody = cbody[clen+3:]
			if len(cbody) < 3 {
				break
			}
		}
	}

	return i, nil
}

type clientInfo struct {
	version string
	client  []*x509.Certificate
}

func watchHandshake(r io.Reader) (*clientInfo, error) {
	i := &clientInfo{}
	i.version = "<unknown>"
	for {
		rec, err := readRecord(r)
		if err != nil {
			return nil, err
		}
		if rec.ct == recordTypeHandshake {
			hs, err := parseHandshake(rec.body)
			if err != nil {
				return nil, err
			}

			if hs.ht == handshakeClientHello {
				if hs.version == 0x0303 {
					i.version = "TLSv1.2"
				} else if hs.version == 0x0304 {
					i.version = "TLSv1.3"
				}
			} else if hs.ht == handshakeCertificate {
				for _, c := range hs.cert {
					crt, err := x509.ParseCertificate(c)
					if err != nil {
						return nil, fmt.Errorf("invalid certificate: %v", err)
					}
					i.client = append(i.client, crt)
				}
			}
		} else {
			// Unencrypted handshake done
			break
		}
	}

	return i, nil
}

func tlsHandler(c net.Conn) {
	defer c.Close()
	log.Printf("TLS %s -> %s, open", c.LocalAddr(), c.RemoteAddr())

	// Proxy to client HTTPS test site for now
	t, err := net.Dial("tcp", "client.badssl.com:443")
	if err != nil {
		log.Printf("Unable to dial backend")
		return
	}
	defer t.Close()
	go io.Copy(c, t)

	tr := io.TeeReader(c, t)
	for {
		info, err := watchHandshake(tr)
		if err != nil {
			log.Printf("Client handshake failed: %v", err)
			hsFail(c, alertHandshakeFailure)
			hsFail(t, alertHandshakeFailure)
			return
		}

		client := "<none>"
		authorized := false
		if len(info.client) > 0 {
			client = info.client[0].Subject.String()
			authorized = true
		}
		log.Printf("TLS %s -> %s: handshake version=%s, client=%s", c.LocalAddr(), c.RemoteAddr(), info.version, client)

		if !authorized {
			log.Printf("TLS %s -> %s: not authorized, rejecting", c.LocalAddr(), c.RemoteAddr())
			hsFail(c, alertAccessDenied)
			hsFail(t, alertHandshakeFailure)
			return
		}

		log.Printf("TLS %s -> %s: authorized, passing through", c.LocalAddr(), c.RemoteAddr())
		// The rest we do not care about
		io.Copy(ioutil.Discard, tr)
	}
}

func httpServer(s net.Listener) {
	for {
		c, err := s.Accept()
		if err != nil {
			log.Fatalf("Unable to accept new HTTP client: %v", err)
		}
		go httpHandler(c)
	}
}

func tlsServer(s net.Listener) {
	for {
		c, err := s.Accept()
		if err != nil {
			log.Fatalf("Unable to accept new TLS client: %v", err)
		}
		go tlsHandler(c)
	}
}

func main() {
	// Let's Encrypt server to handle HTTP-01 challenges as well as serve
	// redirects.
	le, err := net.Listen("tcp", "[::]:80")
	if err != nil {
		log.Fatalf("Unable to listen on HTTP port: %v", err)
	}

	// TODO(#1): Support TPROXY
	s, err := net.Listen("tcp", "[::]:443")
	if err != nil {
		log.Fatalf("Unable to listen on TLS port: %v", err)
	}

	go httpServer(le)
	go tlsServer(s)

	log.Printf("Running...")

	select {}
}
