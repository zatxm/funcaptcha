package funcaptcha

import (
	"encoding/json"
	"fmt"
	"net/url"
)

func toJSON(data interface{}) string {
	str, _ := json.Marshal(data)
	return string(str)
}

func jsonToForm(data string) string {
	// Unmarshal into map
	var form_data map[string]interface{}
	json.Unmarshal([]byte(data), &form_data)
	// Use reflection to convert to form data
	var form url.Values = url.Values{}
	for k, v := range form_data {
		form.Add(k, fmt.Sprintf("%v", v))
	}
	return form.Encode()
}
