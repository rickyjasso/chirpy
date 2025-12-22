package main

import (
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func main() {
	mux := http.NewServeMux()
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
	}
	mux.Handle("/app/", http.StripPrefix("/app/", apiCfg.middlewareMetrics(http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /healthz", handlerHealth)
	mux.HandleFunc("GET /metrics", apiCfg.handlerMetrics)
	mux.HandleFunc("POST /reset", apiCfg.handlerReset)

	server := http.Server{
		Handler: mux,
		Addr:    ":" + "8080",
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
