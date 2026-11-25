package main

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

func probe(addr string) error {
	host, port, e := net.SplitHostPort(addr)
	if e != nil {
		return errors.New("invalid probe address")
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	target := url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: "/healthz"}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := http.Client{Timeout: 3 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("health probe redirect refused") }}
	response, e := client.Get(target.String())
	if e != nil {
		return errors.New("health probe failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("health probe returned non-200 status")
	}
	return nil
}
