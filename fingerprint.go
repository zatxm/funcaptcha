package funcaptcha

import (
	"fmt"
	"reflect"
	"strings"
)

func prepareF(f []map[string]interface{}) string {
	var res []string
	for _, val := range f {
		switch reflect.TypeOf(val).Kind() {
		case reflect.Slice:
			s := reflect.ValueOf(val)
			sliceOfString := make([]string, s.Len())
			for i := 0; i < s.Len(); i++ {
				sliceOfString[i] = fmt.Sprintf("%v", s.Index(i).Interface())
			}
			res = append(res, strings.Join(sliceOfString, ";"))
		default:
			res = append(res, fmt.Sprintf("%v", val))
		}
	}
	return strings.Join(res, "~~~")
}

func getF(f []map[string]interface{}) string {
	return getMurmur128String(prepareF(f), 31)
}
