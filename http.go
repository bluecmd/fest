package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
)

func httpLog(r *http.Request, format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	l := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	log.Printf("HTTP %s -> %s, host=%s, method=%s, url=%q, %s", r.RemoteAddr, l, r.Host, r.Method, r.URL, s)
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	defer httpLog(r, "close")
	httpLog(r, "open")
}
