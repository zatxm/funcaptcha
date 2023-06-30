package funcaptcha

import (
	"fmt"
	"strings"
)

func prepareF(f map[string]string) string {
	var res []string
	for _, val := range f {
		res = append(res, fmt.Sprintf("%v", val))

	}
	return strings.Join(res, "~~~")
}

func getF(f map[string]string) string {
	return getMurmur128String(prepareF(f), 31)
}
