package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"

	pb "github.com/bluecmd/fest/proto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	festCookie = "FestAuth"

	Protocol_UNKNOWN Protocol = 0
	Protocol_HTTP1   Protocol = 1
	Protocol_HTTP2   Protocol = 2
)

var (
	errDone = errors.New("done")

	// Used to debug H2 frames
	dumpH2 = false
)

type Logger interface {
	Infof(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}

type Protocol int

// TODO(bluecmd): See https://github.com/golang/go/issues/36673 to make this easier
type singleConnListener struct {
	conn net.Conn
	done chan bool
	used bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.used {
		// Block until the first connection has been handled to avoid the server shuting down too early
		<-l.done
		return nil, errDone
	}
	l.used = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	// nop
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func extractCookie(cookies []string) (string, error) {
	header := http.Header{}
	for _, v := range cookies {
		header.Add("Cookie", v)
	}
	r := http.Request{Header: header}

	c, err := r.Cookie(festCookie)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func authz(s *session, authz *pb.Authorization) bool {
	for _, u := range authz.GetUser() {
		if u.GetName() == s.User && u.Provider == s.Provider {
			return true
		}
	}
	return false
}

func authErr(err error) (*session, Protocol, error) {
	return nil, Protocol_UNKNOWN, err
}

func authConn(l Logger, cs tls.ConnectionState, in io.Reader) (*session, Protocol, error) {
	if len(cs.VerifiedChains) > 0 {
		// TOOD(bluecmd): mTLS verification here
		// s := newEphemeralSession()
		// defer s.Forget()
		return authErr(fmt.Errorf("client cert authn not implemented"))
	} else {
		proto := Protocol_UNKNOWN
		// HTTP-cookie based authn.
		// This requires the first frame to be a http1 or h2 header that presents
		// a cookie header.
		var cookies []string

		// While we have the hint in ALPN, sometimes HTTP/2 is being used without ALPN,
		// notably gRPC. Look for the preface method PRI to see if this is HTTP/2.
		f3b := make([]byte, 3)
		if _, err := in.Read(f3b); err != nil {
			return authErr(err)
		}

		// Re-add the bytes
		in = io.MultiReader(bytes.NewReader(f3b), in)
		if cs.NegotiatedProtocol == "h2" || string(f3b) == "PRI" {
			// Read h2 preface
			preb := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(in, preb); err != nil {
				return authErr(err)
			} else if !bytes.Equal(preb, []byte(http2.ClientPreface)) {
				return authErr(fmt.Errorf("invalid h2 preface %q", preb))
			}
			// Read h2 frame, expecting SETTINGS followed by HEADERS
			fr := http2.NewFramer(ioutil.Discard, in)
			fr.ReadMetaHeaders = hpack.NewDecoder(4096 /* initial table size */, nil)
			// Write server preface as the empty settings frame
			// NOTE: This is a bit shady.
			// My testing shows that this is the only interactive thing we need to do
			// as a server to make the client go "Cool, I'm going to send you everything
			// and you can take your time to process it, m'kay?". My initial implementation
			// of this ack'd SETTINGS frames and stuff, until HEADERS was seen - at which
			// point the connections were glued together and some ACKs were dropped to
			// not confuse the clients. Well, the clients (noteably cURL) were really
			// confused about that. So I tried a few things, and it turns out the following
			// seems to work pretty good. I.e., we only preface and then let the client
			// send us all the data we need. If a client shows up that really wants
			// us to ack the initial SETTINGS before sending the HEADERS, that client
			// will not work with this code.
			if err := fr.WriteSettings(); err != nil {
				return authErr(err)
			}
			for {
				frm, err := fr.ReadFrame()
				if err != nil {
					return authErr(fmt.Errorf("failed to read h2 frame: %v", err))
				}
				if frm.Header().Type == http2.FrameHeaders {
					hfrm := frm.(*http2.MetaHeadersFrame)
					method := ""
					ct := ""
					// TODO(bluecmd): For gRPC, any metadata set will end up as headers here.
					// Looking at e.g. "content-type" = "application/grpc" and extracing some
					// nice authn header might make for a good integration when not using mTLS certs.
					for _, f := range hfrm.Fields {
						if f.Name == ":method" {
							method = f.Value
						} else if f.Name == "cookie" {
							cookies = append(cookies, f.Value)
						} else if f.Name == "content-type" {
							ct = f.Value
						}
					}
					l.Infof("h2 request, method=%q, content-type=%q", method, ct)
					proto = Protocol_HTTP2
					break
				}
				// ignore any other frames
			}
		} else {
			// Read http1 frame
			req, err := http.ReadRequest(bufio.NewReader(in))
			if err != nil {
				return authErr(fmt.Errorf("failed to read initial http1 frame: %v", err))
			}
			l.Infof("http1.1 request, method=%q", req.Method)
			proto = Protocol_HTTP1
			cookies = req.Header["Cookie"]
		}

		cookie, err := extractCookie(cookies)
		if err == http.ErrNoCookie {
			return nil, proto, nil
		} else if err != nil {
			return authErr(err)
		}

		s, err := validateSessionCookie(cookie)
		return s, proto, err
	}
	return authErr(fmt.Errorf("no auth logic for connection"))
}

func backendServeConn(l Logger, c *tls.Conn, hello io.Reader, pb *pb.Backend) error {
	var bc net.Conn
	var err error

	if tls := pb.GetTls(); tls != nil {
		bc, err = newTLSBackendConn(tls, c.ConnectionState().NegotiatedProtocol)
	} else if plain := pb.GetPlain(); plain != nil {
		bc, err = newPlainBackendConn(plain, c.ConnectionState().NegotiatedProtocol)
	} else {
		return fmt.Errorf("type not implemented")
	}

	if err != nil {
		return err
	}
	defer bc.Close()

	return glue(l, hello, c, bc, c, bc)
}

// Glue together the backend and the client to the best of our ability
func glue(l Logger, hello, cIn, bcIn io.Reader, cOut, bcOut io.Writer) error {
	if dumpH2 {
		p1r, p1w := io.Pipe()
		p2r, p2w := io.Pipe()
		p3r, p3w := io.Pipe()
		p4r, p4w := io.Pipe()
		cIn = io.TeeReader(cIn, p1w)
		bcIn = io.TeeReader(bcIn, p2w)
		cOut = io.MultiWriter(cOut, p3w)
		bcOut = io.MultiWriter(bcOut, p4w)
		for _, r := range []struct {
			r    io.Reader
			skip int
			s    string
		}{
			{p1r, 0, "client in"},
			{p2r, 0, "backend in"},
			{p3r, 0, "client out"},
			{p4r, len(http2.ClientPreface), "backend out"},
		} {
			go func(r io.Reader, skip int, s string) {
				fr := http2.NewFramer(ioutil.Discard, r)
				io.CopyN(ioutil.Discard, r, int64(skip))
				for {
					frm, err := fr.ReadFrame()
					if err != nil {
						l.Debugf("%s: Frame read error: %v", s, err)
						return
					}
					l.Debugf("%14s: %+v", s, frm)
				}
			}(r.r, r.skip, r.s)
		}
	}

	// Copy whatever we have already read from the client straight to the backend
	if _, err := io.Copy(bcOut, hello); err != nil {
		return err
	}

	errc := make(chan error)
	go func() {
		_, err := io.Copy(cOut, bcIn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(bcOut, cIn)
		errc <- err
	}()
	if err := <-errc; err != nil {
		return fmt.Errorf("read: %v", err)
	}
	return nil
}

func newPlainBackendConn(pb *pb.PlainBackend, alpn string) (net.Conn, error) {
	return net.Dial("tcp", pb.GetEndpoint())
}

func newTLSBackendConn(pb *pb.TLSBackend, alpn string) (net.Conn, error) {
	np := []string{}
	if alpn != "" {
		np = append(np, alpn)
	}
	return tls.Dial("tcp", pb.GetEndpoint(), &tls.Config{
		InsecureSkipVerify: pb.GetSkipVerify(),
		NextProtos:         np,
	})
}

func authHttpLog(r *http.Request, format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	l := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	log.Printf("AuthHTTP %s -> %s, host=%q, method=%q, path=%q, %s", r.RemoteAddr, l, r.Host, r.Method, r.URL.Path, s)
}

func authServeConn(c *tls.Conn, svc *Service) error {
	done := make(chan bool)
	err := http.Serve(&singleConnListener{conn: c, done: done}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHTTPHandler(w, r)
		done <- true
	}))
	if err == errDone {
		return nil
	}
	return err
}

func authHTTPHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	eid := q.Get("eid")
	if eid == "" {
		authHttpLog(r, "session validation failed: no eid supplied")
		http.NotFound(w, r)
		return
	}
	nonce := q.Get("nonce")
	if nonce == "" {
		authHttpLog(r, "session validation failed: no nonce supplied")
		http.NotFound(w, r)
		return
	}
	cb := q.Get("callback")
	if cb == "" {
		authHttpLog(r, "session validation failed: no callback supplied")
		http.NotFound(w, r)
		return
	}
	s, err := validateEncryptedSessionID(eid, nonce)
	if err != nil {
		authHttpLog(r, "session validation failed: %v", err)
		http.NotFound(w, r)
		return
	}
	u := &url.URL{
		Scheme: "https",
		Host:   cb,
	}
	s.Callback = u.String()

	// TODO: Real values from oauth2 flow here
	s.User = "test"
	s.Provider = pb.Provider_GITHUB

	http.Redirect(w, r, s.Callback, 302)
}

func redirectAuthn(c *tls.Conn, proto Protocol, svc *Service) error {
	if proto == Protocol_HTTP2 {
		// TODO(bluecmd): This should be easy enough to implement
		return fmt.Errorf("http2 redirect not implemented")
	}
	domain := svc.pb.GetName()
	if proto == Protocol_HTTP1 {
		r := &http.Response{
			StatusCode: 302,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		ur := &url.URL{
			Scheme: "https",
			Host:   *authDomain,
		}
		s := newSession()
		q := ur.Query()
		eid, nonce := s.EncryptedID()
		q["eid"] = []string{eid}
		q["nonce"] = []string{nonce}
		q["callback"] = []string{domain}
		ur.RawQuery = q.Encode()
		r.Header = make(http.Header)
		r.Header.Add("host", domain)
		r.Header.Add("set-cookie", s.Cookie(domain))
		r.Header.Add("location", ur.String())
		r.Write(c)
		return nil
	}
	return fmt.Errorf("unknown protocol specified (%v)", proto)
}
