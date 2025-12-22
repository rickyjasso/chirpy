package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	hits := cfg.fileserverHits.Load()
	html := fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>
        `, int(hits))

	w.Write([]byte(html))

}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Metrics reset to 0"))
}

func handlerHealth(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))

}

func handlerValidateChirp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	type requestBody struct {
		Body string `json:"body"`
	}

	type responseBody struct {
		CleanedBody string `json:"cleaned_body"`
	}

	decoder := json.NewDecoder(r.Body)
	var req requestBody
	err := decoder.Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	if len(req.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long!", nil)
		return
	}

	invalidWords := []string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}

	text := req.Body
	words := strings.Split(text, " ")
	for i, word := range words {
		for _, inv := range invalidWords {
			if strings.EqualFold(inv, word) {
				words[i] = "****"
			}
		}
	}

	respondWithJSON(w, http.StatusOK, responseBody{
		CleanedBody: strings.Join(words, " "),
	})

}
