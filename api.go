package funcaptcha

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

var (
	jar     = tls_client.NewCookieJar()
	options = []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(360),
		tls_client.WithClientProfile(tls_client.Safari_IOS_16_0),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar), // create cookieJar instance and pass it as argument
	}
	client tls_client.HttpClient
)

func init() {
	cli, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	client = cli
	proxy := os.Getenv("http_proxy")
	if proxy != "" {
		client.SetProxy(proxy)
	}
}

func SetTLSClient(cli *tls_client.HttpClient) {
	client = *cli
}

func GetOpenAIToken() (string, string, error) { // token, hex, error
	form, hex := GetForm()
	req, _ := http.NewRequest(http.MethodPost, "https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147", strings.NewReader(form))
	req.Header = headers
	req.Header.Set("Referer", fmt.Sprintf("https://tcr9i.chat.openai.com/v2/1.5.2/enforcement.%s.html", hex))
	resp, err := client.Do(req)
	if err != nil {
		return "", hex, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", hex, errors.New("status code " + resp.Status)
	}
	type arkose_response struct {
		Token string `json:"token"`
	}
	var arkose arkose_response
	err = json.NewDecoder(resp.Body).Decode(&arkose)
	if err != nil {
		return "", hex, err
	}
	if !strings.Contains(arkose.Token, "|rid=") || !strings.Contains(arkose.Token, "|sup=") {
		return arkose.Token, hex, errors.New("captcha required")
	}
	return arkose.Token, hex, nil
}

func GetForm() (string, string) {
	bda, hex := getBDA()
	bda = base64.StdEncoding.EncodeToString([]byte(bda))
	form := url.Values{
		"bda":          {bda},
		"public_key":   {"35536E1E-65B4-4D96-9D97-6ADB7EFF8147"},
		"site":         {"https://chat.openai.com"},
		"userbrowser":  {bv},
		"capi_version": {"1.5.2"},
		"capi_mode":    {"lightbox"},
		"style_theme":  {"default"},
		"rnd":          {strconv.FormatFloat(rand.Float64(), 'f', -1, 64)},
	}
	return form.Encode(), hex
}

func randomHex(length int) string {
	chars := []rune("0123456789abcdef")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

func getBDA() (string, string) {
	hex := randomHex(32)
	var feList []string
	for _, feMap := range fe {
		for k, v := range feMap {
			if k == "S" ||
				k == "AS" ||
				k == "JSF" ||
				k == "T" {
				v = strings.ReplaceAll(v.(string), ";", ",")
			} else if k == "CFP" {
				v = 1941002709
			} else if k == "P" {
				v = "Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF"
			}

			feList = append(feList, fmt.Sprintf("%v:%v", k, v))
		}
	}
	feJson, _ := json.Marshal(feList)
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/1000000000)
	f := getMurmur128String(prepareF(fe), 31)
	bx := fmt.Sprintf(bx_template,
		f,
		base64.StdEncoding.EncodeToString([]byte(timestamp)),
		getWindowHash(),
		getWindowProtoChainHash(),
		hex,
		string(feJson),
	)

	bt := time.Now().UnixMicro() / 1000000
	bw := strconv.FormatInt(bt-(bt%21600), 10)
	return encrypt(bx, bv+bw), hex
}
