package funcaptcha

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const arkPreURL = "https://tcr9i.chat.openai.com/fc/gt2/"

var initVer, initHex string

var arkCookies []*http.Cookie

type arkReq struct {
	arkURL    string
	arkBx     string
	arkHeader http.Header
	arkBody   url.Values
}

var (
	jar     = tls_client.NewCookieJar()
	options = []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(360),
		tls_client.WithClientProfile(profiles.Chrome_117),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar),
	}
	client  *tls_client.HttpClient
	proxy   = os.Getenv("http_proxy")
	authArk *arkReq
	chatArk *arkReq
)

type kvPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type cookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Expires string `json:"expires"`
}
type postBody struct {
	Params []kvPair `json:"params"`
}
type request struct {
	URL      string   `json:"url"`
	Headers  []kvPair `json:"headers,omitempty"`
	PostData postBody `json:"postData,omitempty"`
	Cookies  []cookie `json:"cookies,omitempty"`
}
type entry struct {
	StartedDateTime string  `json:"startedDateTime"`
	Request         request `json:"request"`
}
type logData struct {
	Entries []entry `json:"entries"`
}
type HARData struct {
	Log logData `json:"log"`
}

func readHAR() {
	file, err := os.ReadFile("chat.openai.com.har")
	if err != nil {
		return
	}
	var harFile HARData
	err = json.Unmarshal(file, &harFile)
	if err != nil {
		println("Error: not a HAR file!")
		return
	}
	for _, v := range harFile.Log.Entries {
		if strings.HasPrefix(v.Request.URL, arkPreURL) {
			if authArk == nil || chatArk == nil {
				var tmpArk arkReq
				tmpArk.arkURL = v.Request.URL
				if v.StartedDateTime == "" {
					println("Error: no arkose request!")
					continue
				}
				t, _ := time.Parse(time.RFC3339, v.StartedDateTime)
				bw := getBw(t.Unix())
				fallbackBw := getBw(t.Unix() - 21600)
				tmpArk.arkHeader = make(http.Header)
				for _, h := range v.Request.Headers {
					// arkHeader except cookie & content-length
					if !strings.EqualFold(h.Name, "content-length") && !strings.EqualFold(h.Name, "cookie") && !strings.HasPrefix(h.Name, ":") {
						tmpArk.arkHeader.Set(h.Name, h.Value)
						if strings.EqualFold(h.Name, "user-agent") {
							bv = h.Value
						}
					}
				}
				arkCookies = []*http.Cookie{}
				for _, cookie := range v.Request.Cookies {
					expire, _ := time.Parse(time.RFC3339, cookie.Expires)
					if expire.After(time.Now()) {
						arkCookies = append(arkCookies, &http.Cookie{Name: cookie.Name, Value: cookie.Value, Expires: expire.UTC()})
					}
				}
				var arkType string
				tmpArk.arkBody = make(url.Values)
				for _, p := range v.Request.PostData.Params {
					// arkBody except bda & rnd
					if p.Name == "bda" {
						cipher, err := url.QueryUnescape(p.Value)
						if err != nil {
							panic(err)
						}
						tmpArk.arkBx = Decrypt(cipher, bv+bw, bv+fallbackBw)
					} else if p.Name != "rnd" {
						query, err := url.QueryUnescape(p.Value)
						if err != nil {
							panic(err)
						}
						tmpArk.arkBody.Set(p.Name, query)
						if p.Name == "site" {
							if strings.Contains(p.Value, "auth0.") {
								arkType = "auth"
								authArk = &tmpArk
							} else if strings.Contains(p.Value, "chat.") {
								arkType = "chat"
								chatArk = &tmpArk
							}
						}
					}
				}
				if tmpArk.arkBx != "" {
					println("success read " + arkType + " arkose")
				} else {
					println("failed to decrypt HAR file")
				}
			} else {
				break
			}
		}
	}

}

//goland:noinspection GoUnhandledErrorResult
func init() {
	initVer = "1.5.4"
	initHex = "cd12da708fe6cbe6e068918c38de2ad9" // should be fixed associated with version.
	readHAR()
	cli, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	u, _ := url.Parse(arkPreURL)
	cli.GetCookieJar().SetCookies(u, arkCookies)
	client = &cli
	if proxy != "" {
		(*client).SetProxy(proxy)
	}
}

//goland:noinspection GoUnusedExportedFunction
func SetTLSClient(cli *tls_client.HttpClient) {
	u, _ := url.Parse(arkPreURL)
	(*cli).GetCookieJar().SetCookies(u, arkCookies)
	client = cli
}

func GetOpenAIAuthToken(puid string, proxy string) (string, error) {
	token, err := sendRequest(0, "", puid, proxy)
	return token, err
}

func GetOpenAIAuthTokenWithBx(bx string, puid string, proxy string) (string, error) {
	token, err := sendRequest(0, getBdaWitBx(bx), puid, proxy)
	return token, err
}

func GetOpenAIToken(puid string, proxy string) (string, error) {
	token, err := sendRequest(1, "", puid, proxy)
	return token, err
}

func GetOpenAITokenWithBx(bx string, puid string, proxy string) (string, error) {
	token, err := sendRequest(1, getBdaWitBx(bx), puid, proxy)
	return token, err
}

//goland:noinspection SpellCheckingInspection,GoUnhandledErrorResult
func sendRequest(arkType int, bda string, puid string, proxy string) (string, error) {
	var tmpArk *arkReq
	if arkType == 0 {
		tmpArk = authArk
	} else {
		tmpArk = chatArk
	}
	if tmpArk == nil || tmpArk.arkBx == "" || len(tmpArk.arkBody) == 0 || len(tmpArk.arkHeader) == 0 {
		return "", errors.New("a valid HAR file required")
	}
	if proxy != "" {
		(*client).SetProxy(proxy)
	}
	if bda == "" {
		bda = getBDA(arkType)
	}
	tmpArk.arkBody.Set("bda", base64.StdEncoding.EncodeToString([]byte(bda)))
	tmpArk.arkBody.Set("rnd", strconv.FormatFloat(rand.Float64(), 'f', -1, 64))
	req, _ := http.NewRequest(http.MethodPost, tmpArk.arkURL, strings.NewReader(tmpArk.arkBody.Encode()))
	req.Header = tmpArk.arkHeader.Clone()
	if puid != "" {
		req.Header.Set("cookie", "_puid="+puid+";")
	}
	resp, err := (*client).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("status code " + resp.Status)
	}

	type arkoseResponse struct {
		Token string `json:"token"`
	}
	var arkose arkoseResponse
	err = json.NewDecoder(resp.Body).Decode(&arkose)
	if err != nil {
		return "", err
	}
	// Check if rid is empty
	if !strings.Contains(arkose.Token, "sup=1|rid=") {
		return arkose.Token, errors.New("captcha required")
	}

	return arkose.Token, nil
}

//goland:noinspection SpellCheckingInspection
func getBDA(arkType int) string {
	var bx string
	if arkType == 0 {
		bx = authArk.arkBx
	} else {
		bx = chatArk.arkBx
	}
	if bx == "" {
		bx = fmt.Sprintf(bx_template,
			getF(),
			getN(),
			getWh(),
			webglExtensions,
			getWebglExtensionsHash(),
			webglRenderer,
			webglVendor,
			webglVersion,
			webglShadingLanguageVersion,
			webglAliasedLineWidthRange,
			webglAliasedPointSizeRange,
			webglAntialiasing,
			webglBits,
			webglMaxParams,
			webglMaxViewportDims,
			webglUnmaskedVendor,
			webglUnmaskedRenderer,
			webglVsfParams,
			webglVsiParams,
			webglFsfParams,
			webglFsiParams,
			getWebglHashWebgl(),
			initVer,
			initHex,
			getFe(),
			getIfeHash(),
		)
	} else {
		re := regexp.MustCompile(`"key"\:"n","value"\:"\S*?"`)
		bx = re.ReplaceAllString(bx, `"key":"n","value":"`+getN()+`"`)
	}
	bt := getBt()
	bw := getBw(bt)
	return Encrypt(bx, bv+bw)
}

func getBt() int64 {
	return time.Now().UnixMicro() / 1000000
}

func getBw(bt int64) string {
	return strconv.FormatInt(bt-(bt%21600), 10)
}

func getBdaWitBx(bx string) string {
	bt := getBt()
	bw := getBw(bt)
	return Encrypt(bx, bv+bw)
}
