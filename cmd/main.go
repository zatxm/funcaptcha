package main

import (
	"fmt"
	"log"

	"github.com/acheong08/funcaptcha"
)

func main() {
	token, hex, err := funcaptcha.GetOpenAITokenWithBx(`[{"key":"enhanced_fp","value":[{"key":"navigator_battery_charging","value":true}]},{"key":"fe","value":["DNT:1","L:zh-CN","D:24","PR:1","S:1920,1080","AS:1920,1080","TO:-480","SS:true","LS:true","IDB:true","B:false","ODB:true","CPUC:unknown","PK:Linux x86_64","CFP:11866 se","H:16","SWF:false"]}]`)
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
	_, err = funcaptcha.DownloadChallenge(session.ConciseChallenge.URLs, false)
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
	err = session.SubmitAnswer(index, false)
	if err != nil {
		log.Fatalf("error submitting answer: %v\n", err)
	}
}
