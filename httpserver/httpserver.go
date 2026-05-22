package httpserver

import (
	"fmt"
	"net/http"
)

func StartHTTPServer(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "TLS termination works. Requested document: %s\n", r.URL.Path)
	})
	return http.ListenAndServe(addr, mux)
}
