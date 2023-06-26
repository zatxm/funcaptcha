# funcaptcha

This is a port of project [funcaptcha](https://github.com/noahcoolboy/funcaptcha) to golang.

Usage for OpenAI
```go
import (
  arkose "github.com/acheong08/funcaptcha"
}

func main(){
  token, err := arkose.GetOpenAIToken()
  if err != nil {
    panic(err)
  }
  fmt.Println(token) // Used for gpt-4 requests
}
