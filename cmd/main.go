package main

import (
	"log"

	"github.com/acheong08/funcaptcha"
)

func main() {
	token, hex, err := funcaptcha.GetOpenAIToken()
	log.Println(token)

	if err == nil {
		return
	}
	log.Printf("error getting token: %v\n", err)
	// Start a challenge
	session, err := funcaptcha.StartChallenge(token, hex)
	if err != nil {
		log.Fatalf("error starting challenge: %v\n", err)
	}
	log.Println("Challenge started!")

	err = session.RequestChallenge(true)
	if err != nil {
		log.Fatalf("error requesting challenge: %v\n", err)
	}
	log.Println(session.ConciseChallenge)
	log.Println("Downloading challenge")
	err = funcaptcha.DownloadChallenge(session.ConciseChallenge.URLs)
	if err != nil {
		log.Fatalf("error downloading challenge: %v\n", err)
	}

}
