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
	bv     = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.46"
)

func init() {
	cli, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	client = &cli
	proxy := os.Getenv("http_proxy")
	if proxy != "" {
		(*client).SetProxy(proxy)
	}
}

func SetTLSClient(cli *tls_client.HttpClient) {
	client = cli
}

func GetOpenAIToken() (string, string, error) { // token, hex, error
	form, hex := GetForm()
	req, _ := http.NewRequest(http.MethodPost, "https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147", strings.NewReader(form))
	req.Header = headers
	req.Header.Set("Referer", fmt.Sprintf("https://tcr9i.chat.openai.com/v2/1.5.2/enforcement.%s.html", hex))
	resp, err := (*client).Do(req)
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
	fe := `{"key":"fe","value":["DNT:1","L:en-US","D:24","PR:2","S:1128,752","AS:1128,724","TO:-480","SS:true","LS:true","IDB:true","B:false","ODB:true","CPUC:unknown","PK:Linux x86_64","CFP:-1849310688","FR:false","FOS:false","FB:false","JSF:Andale Mono,Arial,Arial Black,Calibri,Cambria,Comic Sans MS,Courier,Courier New,Georgia,Helvetica,Impact,MS Gothic,MS PGothic,Times,Times New Roman,Trebuchet MS,Verdana","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:8","SWF:false"]}`
	var fe_json struct {
		Key   string   `json:"key"`
		Value []string `json:"value"`
	}
	err := json.Unmarshal([]byte(fe), &fe_json)
	if err != nil {
		panic(err)
	}
	var fe_val string = "{"
	for _, val := range fe_json.Value {
		val = fmt.Sprintf(`"%s"`, val)
		val = strings.Replace(val, ":", `":"`, 1)
		fe_val += val + ","
	}
	fe_val = fe_val[:len(fe_val)-1] + "}"

	var fe_value_json map[string]string
	err = json.Unmarshal([]byte(fe_val), &fe_value_json)
	if err != nil {
		panic(err)
	}

	f_val := getF(fe_value_json)
	hex := randomHex(32)
	// Generate initial fingerprint
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/1000000000)
	bx := fmt.Sprintf(`[{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"%s"},{"key":"n","value":"%s"},{"key":"wh","value":"%s|%s"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_astc;WEBGL_compressed_texture_etc;WEBGL_compressed_texture_etc1;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"84f554482803d6772e59f755ec15d4e0"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0 (OpenGL ES 2.0 Chromium)"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"},{"key":"webgl_aliased_line_width_range","value":"[1, 7.375]"},{"key":"webgl_aliased_point_size_range","value":"[1, 255]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,64,16384,1024,16384,32,16384,32,16,32,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Google Inc. (Intel)"},{"key":"webgl_unmasked_renderer","value":"ANGLE (Intel, Mesa Intel(R) Xe Graphics (TGL GT2), OpenGL 4.6)"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"82b47b33d22d3b4b75db28c1ac98b4df"},{"key":"user_agent_data_brands","value":"Chromium,Microsoft Edge,Not:A-Brand"},{"key":"user_agent_data_mobile","value":false},{"key":"navigator_connection_downlink","value":5.05},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":50},{"key":"network_info_save_data","value":false},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":8},{"key":"navigator_languages","value":"en-US,en"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1128},{"key":"window_outer_height","value":724},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"},{"key":"video_codecs","value":"{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":""},{"key":"window__ancestor_origins","value":["https://chat.openai.com"]},{"key":"window__tree_index","value":[0]},{"key":"window__tree_structure","value":"[[]]"},{"key":"window__location_href","value":"https://tcr9i.chat.openai.com/v2/1.5.2/enforcement.%s.html#35536E1E-65B4-4D96-9D97-6ADB7EFF8147"},{"key":"client_config__sitedata_location_href","value":"https://chat.openai.com/"},{"key":"client_config__surl","value":"https://tcr9i.chat.openai.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"navigator_battery_charging","value":true},{"key":"audio_fingerprint","value":"124.04347527516074"}]},%s,{"key":"ife_hash","value":"f1456761659ec35d48e3fd3490afe357"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":5,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]`,
		f_val,
		base64.StdEncoding.EncodeToString([]byte(timestamp)),
		getWindowHash(),
		getWindowProtoChainHash(),
		hex,
		fe)

	bt := time.Now().UnixMicro() / 1000000
	bw := strconv.FormatInt(bt-(bt%21600), 10)
	return encrypt(bx, bv+bw), hex
}
