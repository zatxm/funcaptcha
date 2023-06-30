package funcaptcha

import (
	"fmt"
	"strings"
)

func prepareF(f []map[string]interface{}) string {
	var res []string
	for _, val := range f {
		for _, v := range val {
			res = append(res, fmt.Sprintf("%v", v))
		}

	}
	return strings.Join(res, "~~~")
}

func getF(f []map[string]interface{}) string {
	return getMurmur128String(prepareF(f), 31)
}
