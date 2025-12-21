package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir("."))))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))

	})

	server := http.Server{
		Handler: mux,
		Addr:    "localhost:8080",
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
