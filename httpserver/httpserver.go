package main

import (
	"fmt"
	"net/http"
)

func startHTTPServer(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "TLS termination works. Requested document: %s\n", r.URL.Path)
	})
	return http.ListenAndServe(addr, mux)
}
