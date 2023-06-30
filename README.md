# Arkose Fetch

Usage for OpenAI

```go
import (
	"fmt"

	"github.com/acheong08/funcaptcha"
)

func main() {
	token, _ := funcaptcha.GetOpenAIToken()
	fmt.Println(token)
}
```