package main

import (
	"log"
	"net/http"
)

func main() {
	handler := func(w http.ResponseWriter, r *http.Request) {
		xForwardedHost := r.Header.Get("X-Forwarded-Host")
		w.Write([]byte(xForwardedHost))
	}
	http.HandleFunc("/", handler)
	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
