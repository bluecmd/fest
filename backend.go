package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	pb "github.com/bluecmd/fest/proto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	Protocol_UNKNOWN Protocol = 0
	Protocol_HTTP1   Protocol = 1
	Protocol_HTTP2   Protocol = 2
)

var (
	festCookie               = "FestAuth-"
	errDone                  = errors.New("done")
	ErrSessionInstallPending = errors.New("session install pending")

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

func extractCookie(cookies []string) (*session, error) {
	header := http.Header{}
	for _, v := range cookies {
		header.Add("Cookie", v)
	}
	r := http.Request{Header: header}

	if c, err := r.Cookie(festCookie + "-IM"); err == nil {
		s, err := validateSessionCookie(c.Value)
		if err == nil && s.User != "" {
			return s, ErrSessionInstallPending
		}
	}

	c, err := r.Cookie(festCookie)
	if err != nil {
		return nil, err
	}

	return validateSessionCookie(c.Value)
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

		s, err := extractCookie(cookies)
		if err == ErrSessionInstallPending {
			return s, proto, err
		} else if err == http.ErrNoCookie {
			l.Infof("cookie not found")
			return nil, proto, nil
		} else if err != nil {
			l.Infof("cookie extraction error")
			return authErr(err)
		}
		return s, proto, nil
	}
	return authErr(fmt.Errorf("no auth logic for connection"))
}

type backend interface {
	Serve(l Logger, c *tls.Conn, hello io.Reader, s *session) error
}

func backendServeConn(l Logger, c *tls.Conn, hello io.Reader, pb *pb.Backend, s *session) error {
	var bc backend
	var err error

	if p := pb.GetTls(); p != nil {
		bc, err = newTLSBackendConn(p, c.ConnectionState().NegotiatedProtocol)
	} else if p := pb.GetPlain(); p != nil {
		bc, err = newPlainBackendConn(p)
	} else if p := pb.GetHttp(); p != nil {
		bc, err = newHTTPBackendConn(p)
	} else {
		return fmt.Errorf("type not implemented")
	}

	if err != nil {
		return err
	}
	return bc.Serve(l, c, hello, s)
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

type plainBackend struct {
	conn net.Conn
}

func newPlainBackendConn(pb *pb.PlainBackend) (*plainBackend, error) {
	conn, err := net.Dial("tcp", pb.GetEndpoint())
	if err != nil {
		return nil, err
	}
	return &plainBackend{conn: conn}, nil
}

func (b *plainBackend) Serve(l Logger, c *tls.Conn, hello io.Reader, s *session) error {
	defer b.conn.Close()
	return glue(l, hello, c, b.conn, c, b.conn)
}

type httpBackendResponseWriter struct {
	log     Logger
	client  net.Conn
	backend net.Conn
	hdrs    http.Header
	wh      bool
}

func (bw *httpBackendResponseWriter) WriteHeader(code int) {
	bw.log.Infof("response from http backend: %d", code)
	bw.client.Write([]byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n", code, http.StatusText(code))))
	bw.hdrs.Write(bw.client)
	bw.client.Write([]byte("\r\n"))
	bw.wh = true
}

func (bw *httpBackendResponseWriter) Write(p []byte) (int, error) {
	if !bw.wh {
		bw.WriteHeader(http.StatusOK)
	}
	return bw.client.Write(p)
}

func (bw *httpBackendResponseWriter) Header() http.Header {
	if bw.hdrs == nil {
		bw.hdrs = http.Header{}
		bw.hdrs.Add("Proxied-Via", "fest")
	}
	return bw.hdrs
}

type httpBackend struct {
	rp *httputil.ReverseProxy
}

func newHTTPBackendConn(pb *pb.HTTPBackend) (*httpBackend, error) {
	u, err := url.Parse(pb.GetTarget())
	if err != nil {
		return nil, err
	}
	return &httpBackend{httputil.NewSingleHostReverseProxy(u)}, nil
}

func (b *httpBackend) Serve(l Logger, c *tls.Conn, hello io.Reader, s *session) error {
	in := io.MultiReader(hello, c)
	for {
		req, err := http.ReadRequest(bufio.NewReader(in))
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read http1 frame: %v", err)
		}
		l.Infof("http1.1 backend request, method=%q", req.Method)
		rw := &httpBackendResponseWriter{log: l, client: c}
		req.Header.Add("Fest-User", s.User)
		req.Header.Add("Fest-Provider", s.Provider.String())
		b.rp.ServeHTTP(rw, req)
		l.Infof("http1.1 backend request done")
		// TODO: Keep-alive session management
		break
	}
	return nil
}

type tlsBackend struct {
	conn net.Conn
}

func newTLSBackendConn(pb *pb.TLSBackend, alpn string) (*tlsBackend, error) {
	np := []string{}
	if alpn != "" {
		np = append(np, alpn)
	}
	conn, err := tls.Dial("tcp", pb.GetEndpoint(), &tls.Config{
		InsecureSkipVerify: pb.GetSkipVerify(),
		NextProtos:         np,
	})
	if err != nil {
		return nil, err
	}
	return &tlsBackend{conn: conn}, nil
}

func (b *tlsBackend) Serve(l Logger, c *tls.Conn, hello io.Reader, s *session) error {
	defer b.conn.Close()
	return glue(l, hello, c, b.conn, c, b.conn)
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
	if r.URL.Path != "/" {
		authCallback(w, r)
		return
	}
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

	initOauth(w, s)
}

func initOauth(w http.ResponseWriter, s *session) {
	sdata := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, sdata); err != nil {
		panic(fmt.Sprintf("failed to read entropy: %v", err))
	}
	state := hex.EncodeToString(sdata)

	oa := &oauth2.Config{
		ClientID:     HackClientID,
		ClientSecret: HackClientSecret,
		RedirectURL:  HackRedirectURL,
		Endpoint:     github.Endpoint,
	}

	// Save the state in a cookie that we can retrieve after the Oauth is complete.
	// Use a generated suffix to allow multiple sessions to be authed at the same time.
	sc := fmt.Sprintf("%s-OSTATE-%s=%s; Domain=%s; Secure; Max-Age=300", festCookie, state, s.ID(), *authDomain)
	h := w.Header()
	h["host"] = []string{*authDomain}
	h["set-cookie"] = []string{sc}
	h["location"] = []string{oa.AuthCodeURL(state)}
	w.WriteHeader(302)
}

func authCallback(w http.ResponseWriter, r *http.Request) {
	oa := &oauth2.Config{
		ClientID:     HackClientID,
		ClientSecret: HackClientSecret,
		RedirectURL:  HackRedirectURL,
		Endpoint:     github.Endpoint,
	}
	q := r.URL.Query()
	code := q.Get("code")
	if code == "" {
		authHttpLog(r, "oauth callback failed: no code supplied")
		http.NotFound(w, r)
		return
	}

	state := q.Get("state")
	if state == "" {
		authHttpLog(r, "oauth callback failed: no state supplied")
		http.NotFound(w, r)
		return
	}

	var s *session
	for _, cookie := range r.Cookies() {
		if cookie.Name == fmt.Sprintf("%s-OSTATE-%s", festCookie, state) {
			var err error
			s, err = validateSessionCookie(cookie.Value)
			if err != nil {
				authHttpLog(r, "oauth callback failed: session invalid: %v", err)
				http.NotFound(w, r)
				return
			}
		}
	}

	tok, err := oa.Exchange(oauth2.NoContext, code)
	if err != nil {
		authHttpLog(r, "oauth exchange failed: %v", err)
		http.NotFound(w, r)
		return
	}

	client := oa.Client(oauth2.NoContext, tok)
	o, err := client.Get("https://api.github.com/user")
	if err != nil {
		authHttpLog(r, "oauth interrogation failed: %v", err)
		http.NotFound(w, r)
		return
	}
	defer o.Body.Close()
	data, err := ioutil.ReadAll(o.Body)
	if err != nil {
		authHttpLog(r, "oauth interrogation failed: %v", err)
		http.NotFound(w, r)
		return
	}

	type User struct {
		Login string
	}
	var user User

	err = json.Unmarshal(data, &user)
	if err != nil {
		authHttpLog(r, "oauth interrogation failed: json decode: %v", err)
		http.NotFound(w, r)
		return
	}

	s.User = user.Login
	s.Provider = pb.Provider_GITHUB
	authHttpLog(r, "oauth completed for user=%q, provider=%q", s.User, s.Provider)

	sc := fmt.Sprintf("%s-OSTATE-%s=; Domain=%s; Secure; Expires=Thu, 01 Jan 1970 00:00:00 GMT", festCookie, state, *authDomain)
	h := w.Header()
	h["host"] = []string{*authDomain}
	h["set-cookie"] = []string{sc}
	h["location"] = []string{s.Callback}
	w.WriteHeader(302)
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
		r.Header.Add("set-cookie", s.AuthCookie(domain))
		r.Header.Add("location", ur.String())
		r.Write(c)
		return nil
	}
	return fmt.Errorf("unknown protocol specified (%v)", proto)
}

func authzError(c *tls.Conn, proto Protocol, svc *Service) error {
	msg := "403 - user not authorized to this resource"
	if proto == Protocol_HTTP2 {
		// TODO(bluecmd): This should be easy enough to implement
		return fmt.Errorf("http2 error page not implemented")
	}
	domain := svc.pb.GetName()
	if proto == Protocol_HTTP1 {
		r := &http.Response{
			StatusCode: 403,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		r.Header = make(http.Header)
		r.Header.Add("host", domain)
		r.Header.Add("content-type", "text/plain")
		r.ContentLength = int64(len(msg))
		r.Body = ioutil.NopCloser(strings.NewReader(msg))
		r.Write(c)
		return nil
	}
	return fmt.Errorf("unknown protocol specified (%v)", proto)
}

func installSession(c *tls.Conn, proto Protocol, svc *Service, s *session) error {
	if proto == Protocol_HTTP2 {
		// TODO(bluecmd): This should be easy enough to implement
		return fmt.Errorf("http2 session install not implemented")
	}
	domain := svc.pb.GetName()
	if proto == Protocol_HTTP1 {
		r := &http.Response{
			StatusCode: 302,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		r.Header = make(http.Header)
		r.Header.Add("host", domain)
		r.Header.Add("location", "#")
		r.Header.Add("set-cookie", fmt.Sprintf("%s-IM=; Domain=%s; Secure; Expires=Thu, 01 Jan 1970 00:00:00 GMT", festCookie, domain))
		r.Header.Add("set-cookie", s.Cookie(domain))
		r.Write(c)
		return nil
	}
	return fmt.Errorf("unknown protocol specified (%v)", proto)
}

func init() {
	festCookie = festCookie + fmt.Sprintf("%x", time.Now().Unix())
}
