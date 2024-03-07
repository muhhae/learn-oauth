package main

import (
	"log"

	"github.com/joho/godotenv"
	"github.com/muhhae/learn-oauth/authenticator"
	"github.com/muhhae/learn-oauth/router"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Failed to load the env vars: %v", err)
	}

	auth, err := authenticator.NewAuthenticator()
	if err != nil {
		log.Fatalln("Failed to initialize authenticator")
	}

	r := router.New(auth)
	log.Println("Starting server on http://localhost:8080")
	if err := r.Start("localhost:8080"); err != nil {
		log.Fatalln("Error starting server", err)
	}
}
