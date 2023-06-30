package main

import (
	"fmt"
	"log"

	"github.com/acheong08/funcaptcha"
)

func main() {
	token, hex, err := funcaptcha.GetOpenAIToken()
	fmt.Println(token)

	if err == nil {
		return
	}
	fmt.Printf("error getting token: %v\n", err)
	// Start a challenge
	session, err := funcaptcha.StartChallenge(token, hex)
	if err != nil {
		log.Fatalf("error starting challenge: %v\n", err)
	}
	fmt.Println("Challenge started!")

	challenge, err := session.RequestChallenge()
	if err != nil {
		log.Fatalf("error requesting challenge: %v\n", err)
	}
	fmt.Println(challenge)

}
