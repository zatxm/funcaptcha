package main

import (
	"fmt"
	"log"

	"github.com/acheong08/funcaptcha"
)

func main() {
	token, err := funcaptcha.GetOpenAIToken()
	if err != nil {
		log.Fatalf("error getting token: %v", err)
	}
	fmt.Println(token)
}
