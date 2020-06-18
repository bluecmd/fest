package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	http01ChallengeTimeout = 15 * time.Second
)

var (
	http01ChalsMetric = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "fest_http01_active_challenges",
			Help: "The current number of in-memory HTTP-01 challenges",
		},
	)
)

var (
	http01Chal = map[string]string{}
)

func httpLog(r *http.Request, format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	l := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	log.Printf("HTTP %s -> %s, host=%s, method=%s, url=%q, %s", r.RemoteAddr, l, r.Host, r.Method, r.URL, s)
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	defer httpLog(r, "close")
	httpLog(r, "open")

	v, ok := http01Chal[r.URL.Path]
	if ok {
		httpLog(r, "challenge match")
		w.Write([]byte(v))
		return
	}

	httpLog(r, "not-found")
	http.NotFound(w, r)
}

func registerHTTP01Challenge(path, value string) {
	http01Chal[path] = value
	http01ChalsMetric.Set(float64(len(http01Chal)))

	go func() {
		time.Sleep(http01ChallengeTimeout)
		delete(http01Chal, path)
		http01ChalsMetric.Set(float64(len(http01Chal)))
	}()
}
