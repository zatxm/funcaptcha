package main

import (
	"fmt"
	"log"
)

func main() {
	var input int
	_, err := fmt.Scanln(&input)
	if err != nil {
		log.Fatalf("error reading input: %v\n", err)
	}
	log.Println(input)
}
