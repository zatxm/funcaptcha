package funcaptcha

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

var headers = http.Header{
	"Accept":           []string{"*/*"},
	"Accept-Encoding":  []string{"gzip, deflate, br"},
	"Accept-Language":  []string{"en-US,en;q=0.5"},
	"Cache-Control":    []string{"no-cache"},
	"Connection":       []string{"keep-alive"},
	"Content-Type":     []string{"application/x-www-form-urlencoded; charset=UTF-8"},
	"DNT":              []string{"1"},
	"Host":             []string{"tcr9i.chat.openai.com"},
	"Origin":           []string{"https://tcr9i.chat.openai.com"},
	"Sec-Fetch-Dest":   []string{"empty"},
	"Sec-Fetch-Mode":   []string{"cors"},
	"Sec-Fetch-Site":   []string{"same-origin"},
	"TE":               []string{"trailers"},
	"User-Agent":       []string{"Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0"},
	"X-Requested-With": []string{"XMLHttpRequest"},
}

type Session struct {
	Sid          string `json:"sid"`
	SessionToken string `json:"session_token"`
	Hex          string `json:"hex"`
}

type Challenge struct {
	SessionToken         string                 `json:"session_token"`
	ChallengeID          string                 `json:"challengeID"`
	ChallengeURL         string                 `json:"challengeURL"`
	AudioChallengeURLs   []string               `json:"audio_challenge_urls"`
	AudioGameRateLimited interface{}            `json:"audio_game_rate_limited"`
	Sec                  int                    `json:"sec"`
	EndURL               interface{}            `json:"end_url"`
	GameData             map[string]interface{} `json:"game_data"`
	GameSID              string                 `json:"game_sid"`
	SID                  string                 `json:"sid"`
	Lang                 string                 `json:"lang"`
	StringTablePrefixes  []interface{}          `json:"string_table_prefixes"`
	StringTable          map[string]string      `json:"string_table"`
	EarlyVictoryMessage  interface{}            `json:"earlyVictoryMessage"`
	FontSizeAdjustments  interface{}            `json:"font_size_adjustments"`
	StyleTheme           string                 `json:"style_theme"`
}

type initialChallenge struct {
	Sid           string `json:"sid"`
	SessionToken  string `json:"session_token"`
	AnalyticsTier int    `json:"analytics_tier"`
	RenderType    string `json:"render_type"`
	Category      string `json:"category"`
	Action        string `json:"action"`
}

type requestChallenge struct {
	Sid               string `json:"sid"`
	Token             string `json:"token"`
	AnalyticsTier     int    `json:"analytics_tier"`
	RenderType        string `json:"render_type"`
	Lang              string `json:"lang"`
	IsAudioGame       bool   `json:"isAudioGame"`
	APIBreakerVersion string `json:"apiBreakerVersion"`
}

func StartChallenge(full_session, hex string) (*Session, error) {
	headers.Set("Referer", fmt.Sprintf("https://tcr9i.chat.openai.com/fc/assets/ec-game-core/game-core/1.13.0/standard/index.html?session=%s", strings.Replace(full_session, "|", "&", -1)))
	fields := strings.Split(full_session, "|")
	session_token := fields[0]
	sid := strings.Split(fields[1], "=")[1]
	// Convert challenge to url.Values
	v := initialChallenge{
		Sid:           sid,
		SessionToken:  session_token,
		AnalyticsTier: 40,
		RenderType:    "canvas",
		Category:      "Site URL",
		Action:        fmt.Sprintf("https://tcr9i.chat.openai.com/v2/1.5.2/enforcement.%s.html", hex),
	}
	request, _ := http.NewRequest(http.MethodPost, "https://tcr9i.chat.openai.com/fc/a/", strings.NewReader(jsonToForm(toJSON(v))))
	request.Header = headers
	resp, err := (*client).Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	log.Println(string(body))

	return &Session{
		Sid:          sid,
		SessionToken: session_token,
		Hex:          hex,
	}, nil
}

func (c *Session) RequestChallenge() (*Challenge, error) {
	challenge_request := requestChallenge{
		Sid:               c.Sid,
		Token:             c.SessionToken,
		AnalyticsTier:     40,
		RenderType:        "canvas",
		Lang:              "",
		IsAudioGame:       false,
		APIBreakerVersion: "green",
	}
	payload := jsonToForm(toJSON(challenge_request))
	log.Println(payload)
	req, _ := http.NewRequest(http.MethodPost, "https://tcr9i.chat.openai.com/fc/gfct/", strings.NewReader(payload))
	req.Header = headers
	resp, err := (*client).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	log.Println(string(body))
	var challenge_data Challenge
	err = json.Unmarshal(body, &challenge_data)
	return &challenge_data, err

}
