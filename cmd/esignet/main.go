package main

import (
	"log"
	"net/http"
	"os"

	"github.com/ShubhamK-07/MOsip2/internal/server"
)

func main() {
	issuer := "http://localhost:8080"
	if v := os.Getenv("ESIGNET_ISSUER"); v != "" {
		issuer = v
	}
	secret := os.Getenv("ESIGNET_SIGNING_SECRET")
	if secret == "" {
		secret = "dev-signing-secret-change-me"
	}

	h := server.New(server.Config{Issuer: issuer, SigningSecret: secret})
	log.Printf("esignet native-sso server listening on :8080")
	if err := http.ListenAndServe(":8080", h); err != nil {
		log.Fatal(err)
	}
}
