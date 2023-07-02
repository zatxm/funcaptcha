# Arkose Fetch

Usage for OpenAI

```go
import (
	"fmt"

	"github.com/acheong08/funcaptcha"
)

func main() {
	token, _, _ := funcaptcha.GetOpenAIToken()
	fmt.Println(token)
}
```

API:
You can download the binary from releases or `go run cmd/api/main.go`
