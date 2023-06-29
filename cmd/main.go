package main

import (
	"fmt"

	"github.com/linweiyuan/funcaptcha"
)

func main() {
	token, _ := funcaptcha.GetOpenAIToken()
	fmt.Println(token)
}
