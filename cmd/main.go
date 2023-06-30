package main

import (
	"fmt"
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

	err = session.RequestChallenge(false)
	if err != nil {
		log.Fatalf("error requesting challenge: %v\n", err)
	}
	log.Println(session.ConciseChallenge)
	log.Println("Downloading challenge")
	err = funcaptcha.DownloadChallenge(session.ConciseChallenge.URLs)
	if err != nil {
		log.Fatalf("error downloading challenge: %v\n", err)
	}
	log.Println("Challenge downloaded!")
	// User input here
	fmt.Println("Please enter the index of the image based on the following instructions:")
	fmt.Println(session.ConciseChallenge.Instructions)
	var index int
	_, err = fmt.Scanln(&index)
	if err != nil {
		log.Fatalf("error reading input: %v\n", err)
	}
	log.Println(index)
	err = session.SubmitAnswer(index)
	if err != nil {
		log.Fatalf("error submitting answer: %v\n", err)
	}
}
