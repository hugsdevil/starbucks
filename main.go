package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

type (
	// dump request
	DumpTransport struct {
		Debug bool
		io.Writer
		http.RoundTripper
	}
)

const (
	wifiURL     = "http://first.wifi.olleh.com"
	redirectURL = wifiURL + "/webauth/redirection.php"
	issueURL    = wifiURL + "/starbucks/auth_issue.php"
	finalURL    = "http://www.istarbucks.co.kr/util/wireless.do"
	agent       = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0"
	lang        = "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3"
)

var (
	client = &http.Client{
		Transport: &DumpTransport{
			Debug:        false,
			Writer:       os.Stdout,
			RoundTripper: http.DefaultTransport,
		},
	}

	storedCookies = []*http.Cookie{}
)

func (t *DumpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.Debug {
		return t.RoundTripper.RoundTrip(req)
	}

	if dump, err := httputil.DumpRequest(req, true); err != nil {
		return nil, err
	} else {
		t.Write(dump)
		t.Write([]byte{'\n'})
	}

	res, err := t.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if dump, err := httputil.DumpResponse(res, true); err != nil {
		return nil, err
	} else {
		t.Write(dump)
		t.Write([]byte{'\n'})
	}

	return res, err
}

func isRedirect(req *http.Request, res *http.Response) bool {
	return req != res.Request
}

func isReauth(req *http.Request) bool {
	return req.URL.String() == finalURL
}

func addCookies(req *http.Request, res *http.Response) {
	m := map[string]string{}

	for _, cookie := range res.Request.Cookies() {
		m[cookie.Name] = cookie.Value
	}
	for _, cookie := range res.Cookies() {
		m[cookie.Name] = cookie.Value
	}
	for k, v := range m {
		req.AddCookie(&http.Cookie{
			Name: k, Value: v,
		})
	}
}

// make *http.Request to detect network login page
func makeRequestPing() *http.Request {
	req, _ := http.NewRequest("GET", "http://detectportal.firefox.com/success.txt", nil)
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Connection", "keep-alive")

	for _, cookie := range storedCookies {
		req.AddCookie(cookie)
	}

	return req
}

// parse response webauth/index.html
// make request   webauth/redirection.php
func requestRedirect(res *http.Response) (*http.Response, error) {
	defer res.Body.Close()

	ok := false
	rawurl := ""
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		text := scanner.Text()
		if !strings.Contains(text, "location.href") {
			continue
		}

		s := strings.Split(text, "\"")
		if len(s) < 3 {
			continue
		} else if strings.Contains(s[1], redirectURL) {
			ok = true
			rawurl = s[1]
			break
		}
	}

	if !ok {
		if err := scanner.Err(); err != nil {
			return nil, err
		} else {
			return nil, fmt.Errorf("unknown error")
		}
	}

	req, err := http.NewRequest("GET", rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3")
	req.Header.Set("Referer", res.Request.URL.String())
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	addCookies(req, res)

	return client.Do(req)
}

// parse webauth/redirection.php
// if it already connected, then make request final url
// otherwise next step
func parseRedirectAndMakeRequest(res *http.Response) (*http.Request, error) {
	defer res.Body.Close()

	v := url.Values{}
	m := map[string]string{}
	rawurl := finalURL
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		text := scanner.Text()
		if strings.HasPrefix(text, "<!--") {
			continue
		} else if strings.Contains(text, "script") {
			s := strings.Split(text, "\"")
			for i, l := 3, len(s); i < l; i += 4 {
				vals := strings.FieldsFunc(s[i], func(r rune) bool {
					return r == '=' || r == ';'
				})
				if len(vals) < 2 {
					continue
				}
				m[vals[0]] = vals[1]
			}
		} else if strings.Contains(text, "<form") {
			s := strings.Split(text, "\"")
			rawurl = "http://" + res.Request.Host + s[5]
		} else if strings.Contains(text, "input") {
			s := strings.Split(text, "\"")
			v.Set(s[3], s[5])
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	method := "GET"
	body := &strings.Reader{}
	// if it already connected
	if rawurl != finalURL {
		method = "POST"
		body = strings.NewReader(v.Encode())
	}

	req, err := http.NewRequest(method, rawurl, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3")
	req.Header.Set("Referer", res.Request.URL.String())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", body.Len()))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	addCookies(req, res)

	for k, v := range m {
		req.AddCookie(&http.Cookie{
			Name: k, Value: v,
		})
	}

	storedCookies = req.Cookies()

	return req, nil
}

func parseIndexAndMakeResponse(res *http.Response) (*http.Response, error) {
	defer res.Body.Close()

	v := url.Values{}
	first := false
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		text := scanner.Text()
		if !first {
			if strings.Contains(text, "data:  {") {
				first = true
			}
			continue
		} else if strings.Contains(text, "},") {
			break
		}

		s := strings.FieldsFunc(text, func(r rune) bool {
			return r == '\'' || r == '"'
		})

		if len(s) == 0 {
			continue
		}

		if s[1] == "devicecode" {
			v.Add(s[1], "pc")
		} else {
			v.Add(s[1], s[3])
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	body := strings.NewReader(v.Encode())
	req, err := http.NewRequest("POST", issueURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Referer", res.Request.URL.String())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", body.Len()))
	req.Header.Set("Connection", "keep-alive")

	addCookies(req, res)

	storedCookies = req.Cookies()

	return client.Do(req)
}

// check json message
// return json format {"result_cd" = 0000}
func isSuccess(res *http.Response) bool {
	defer res.Body.Close()

	m := map[string]string{}
	dec := json.NewDecoder(res.Body)
	if err := dec.Decode(&m); err != nil {
		return false
	}

	v, ok := m["result_cd"]
	if !ok {
		return false
	} else if v == "3001" {
		return false
	} else {
		return true
	}
}

func connect() error {
	var (
		req *http.Request
		res *http.Response
		err error
	)

	req = makeRequestPing()
	res, err = client.Do(req)
	if err != nil {
		return err
	}

	if !isRedirect(req, res) {
		return nil
	}

	res, err = requestRedirect(res)
	if err != nil {
		return err
	}

	req, err = parseRedirectAndMakeRequest(res)
	if err != nil {
		return nil
	}

	if isReauth(req) {
		return nil
	}

	res, err = client.Do(req)
	if err != nil {
		return err
	}

	res, err = parseIndexAndMakeResponse(res)
	if err != nil {
		return err
	}

	if ok := isSuccess(res); !ok {
		return fmt.Errorf("abnormal request")
	}

	return nil
}

func main() {
	fmt.Println("connect start")

	ch := make(chan struct{})
	go func() {
		ch <- struct{}{}
	}()

	ticker := time.NewTicker(time.Second * 10)
	for {
		select {
		case <-ticker.C:
			fmt.Println("connect reauth")
			go func() {
				ch <- struct{}{}
			}()
		case <-ch:
			for i := 0; i < 3; i++ {
				err := connect()
				if err != nil {
					fmt.Println("connect nok:", err)
					time.Sleep(time.Second * 3)
				} else {
					fmt.Println("connect ok")
					break
				}
			}
		}
	}

	fmt.Println("teminated")
}
