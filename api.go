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
	client *tls_client.HttpClient
)

//goland:noinspection GoUnhandledErrorResult
func init() {
	cli, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	client = &cli
	proxy := os.Getenv("http_proxy")
	if proxy != "" {
		(*client).SetProxy(proxy)
	}
}

//goland:noinspection GoUnusedExportedFunction
func SetTLSClient(cli *tls_client.HttpClient) {
	client = cli
}

//goland:noinspection SpellCheckingInspection,GoUnhandledErrorResult
func GetOpenAIToken() (string, error) {
	bda := getBDA()
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
	req, _ := http.NewRequest(http.MethodPost, "https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("DNT", "1")
	req.Header.Set("Origin", "https://tcr9i.chat.openai.com")
	req.Header.Set("Referer", "https://tcr9i.chat.openai.com/v2/1.5.2/enforcement.64b3a4e29686f93d52816249ecbf9857.html")
	req.Header.Set("User-Agent", bv)
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

	return arkose.Token, nil
}

//goland:noinspection SpellCheckingInspection
func getBDA() string {
	bx := fmt.Sprintf(`
		[{
			"key": "api_type",
			"value": "js"
		}, {
			"key": "p",
			"value": 1
		}, {
			"key": "f",
			"value": "%s"
		}, {
			"key": "n",
			"value": "%s"
		}, {
			"key": "wh",
			"value": "%s"
		}, {
			"key": "enhanced_fp",
			"value": [{
				"key": "webgl_extensions",
				"value": "%s"
			}, {
				"key": "webgl_extensions_hash",
				"value": "%s"
			}, {
				"key": "webgl_renderer",
				"value": "%s"
			}, {
				"key": "webgl_vendor",
				"value": "%s"
			}, {
				"key": "webgl_version",
				"value": "%s"
			}, {
				"key": "webgl_shading_language_version",
				"value": "%s"
			}, {
				"key": "webgl_aliased_line_width_range",
				"value": "%s"
			}, {
				"key": "webgl_aliased_point_size_range",
				"value": "%s"
			}, {
				"key": "webgl_antialiasing",
				"value": "%s"
			}, {
				"key": "webgl_bits",
				"value": "%s"
			}, {
				"key": "webgl_max_params",
				"value": "%s"
			}, {
				"key": "webgl_max_viewport_dims",
				"value": "%s"
			}, {
				"key": "webgl_unmasked_vendor",
				"value": "%s"
			}, {
				"key": "webgl_unmasked_renderer",
				"value": "%s"
			}, {
				"key": "webgl_vsf_params",
				"value": "%s"
			}, {
				"key": "webgl_vsi_params",
				"value": "%s"
			}, {
				"key": "webgl_fsf_params",
				"value": "%s"
			}, {
				"key": "webgl_fsi_params",
				"value": "%s"
			}, {
				"key": "webgl_hash_webgl",
				"value": "%s"
			}, {
				"key": "user_agent_data_brands",
				"value": "Not.A/Brand,Chromium,Google Chrome"
			}, {
				"key": "user_agent_data_mobile",
				"value": false
			}, {
				"key": "navigator_connection_downlink",
				"value": 10.0
			}, {
				"key": "navigator_connection_downlink_max",
				"value": null
			}, {
				"key": "network_info_rtt",
				"value": 150
			}, {
				"key": "network_info_save_data",
				"value": false
			}, {
				"key": "network_info_rtt_type",
				"value": null
			}, {
				"key": "screen_pixel_depth",
				"value": 24
			}, {
				"key": "navigator_device_memory",
				"value": 8
			}, {
				"key": "navigator_languages",
				"value": "zh-CN,en"
			}, {
				"key": "window_inner_width",
				"value": 0
			}, {
				"key": "window_inner_height",
				"value": 0
			}, {
				"key": "window_outer_width",
				"value": 1920
			}, {
				"key": "window_outer_height",
				"value": 1057
			}, {
				"key": "browser_detection_firefox",
				"value": false
			}, {
				"key": "browser_detection_brave",
				"value": false
			}, {
				"key": "audio_codecs",
				"value": "{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"
			}, {
				"key": "video_codecs",
				"value": "{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"
			}, {
				"key": "media_query_dark_mode",
				"value": true
			}, {
				"key": "headless_browser_phantom",
				"value": false
			}, {
				"key": "headless_browser_selenium",
				"value": false
			}, {
				"key": "headless_browser_nightmare_js",
				"value": false
			}, {
				"key": "document__referrer",
				"value": ""
			}, {
				"key": "window__ancestor_origins",
				"value": ["https://chat.openai.com"]
			}, {
				"key": "window__tree_index",
				"value": [2]
			}, {
				"key": "window__tree_structure",
				"value": "[[],[],[]]"
			}, {
				"key": "window__location_href",
				"value": "https://tcr9i.chat.openai.com/v2/1.5.2/enforcement.64b3a4e29686f93d52816249ecbf9857.html#35536E1E-65B4-4D96-9D97-6ADB7EFF8147"
			}, {
				"key": "client_config__sitedata_location_href",
				"value": "https://chat.openai.com"
			}, {
				"key": "client_config__surl",
				"value": "https://tcr9i.chat.openai.com"
			}, {
				"key": "mobile_sdk__is_sdk"
			}, {
				"key": "client_config__language",
				"value": null
			}, {
				"key": "navigator_battery_charging",
				"value": true
			}, {
				"key": "audio_fingerprint",
				"value": "124.04347527516074"
			}]
		}, {
			"key": "fe",
			"value": %s
		}, {
			"key": "ife_hash",
			"value": "%s"
		}, {
			"key": "cs",
			"value": 1
		}, {
			"key": "jsbd",
			"value": "{\"HL\":5,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"
		}]
	`,
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
		getFe(),
		getIfeHash(),
	)

	bt := time.Now().UnixMicro() / 1000000
	bw := strconv.FormatInt(bt-(bt%21600), 10)
	return encrypt(bx, bv+bw)
}
