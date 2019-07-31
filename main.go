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

	Result struct {
		CD string `json:"result_cd"`
	}
)

const (
	firstURL    = "http://detectportal.firefox.com/success.txt"
	wifiURL     = "http://first.wifi.olleh.com"
	redirectURL = wifiURL + "/webauth/redirection.php"
	issueURL    = wifiURL + "/starbucks/auth_issue.php"
	agent       = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0"
	accept      = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	lang        = "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3"
	keepAlive   = "keep-alive"
)

var (
	client = &http.Client{
		Transport: &DumpTransport{
			Debug:        false,
			Writer:       os.Stdout,
			RoundTripper: http.DefaultTransport,
		},
	}
	header = http.Header{
		"User-Agent":      []string{agent},
		"Accept":          []string{accept},
		"Accept-Language": []string{lang},
		"Connection":      []string{keepAlive},

		"Upgrade-Insecure-Requests": []string{"1"},
	}

	debug = false
)

//
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

func responseRedirection(res *http.Response) (*http.Response, error) {
	req, err := http.NewRequest("GET", firstURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3")
	//req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Connection", "keep-alive")

	return client.Do(req)
}

func parseRedirectionAndResponseIndex(res *http.Response) (*http.Response, error) {
	defer res.Body.Close()

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		text := scanner.Text()
		if strings.Contains(text, "location.href") == false {
			continue
		}

		s := strings.Split(text, "\"")
		if len(s) < 3 {
			continue
		} else if strings.Contains(s[1], redirectURL) == false {
			continue
		}

		req, err := http.NewRequest("GET", s[1], nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", agent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3")
		req.Header.Set("Referer", res.Request.URL.String())
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		cookies := res.Cookies()
		for _, cookie := range cookies {
			req.AddCookie(&http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			})
		}

		return client.Do(req)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("no such redirect url: %s or already connected wifi", redirectURL)
}

func parseIndexAndResponseAuth(res *http.Response) (*http.Response, error) {
	defer res.Body.Close()

	v := url.Values{}
	path := ""
	cookies := []*http.Cookie{}
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		text := scanner.Text()
		if strings.Contains(text, "script") {
			s := strings.Split(text, "\"")
			for i, l := 3, len(s); i < l; i += 4 {
				vals := strings.FieldsFunc(s[i], func(r rune) bool {
					return r == '=' || r == ';'
				})
				cookies = append(cookies, &http.Cookie{
					Name:  vals[0],
					Value: vals[1],
				})
			}
		} else if strings.Contains(text, "<form") {
			s := strings.Split(text, "\"")
			path = s[5]
		} else if strings.Contains(text, "input") == true {
			s := strings.Split(text, "\"")
			v.Set(s[3], s[5])
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	body := strings.NewReader(v.Encode())
	req, err := http.NewRequest("POST", wifiURL+path, body)
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

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	cookies = res.Cookies()
	first := true
	for _, cookie := range cookies {
		// only one cookie for PHPSESSID
		if first && cookie.Name == "PHPSESSID" {
			first = false
			continue
		}
		req.AddCookie(&http.Cookie{
			Name:  cookie.Name,
			Value: cookie.Value,
		})
	}

	return client.Do(req)
}

func parseAuthAndResponseIssue(res *http.Response) (*http.Response, error) {
	defer res.Body.Close()

	v := url.Values{}
	on := false
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		text := scanner.Text()
		if !on {
			if strings.Contains(text, "data:  {") {
				on = true
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

	cookies := res.Request.Cookies()
	for _, c := range cookies {
		req.AddCookie(c)
	}

	return client.Do(req)
}

func main() {
	var (
		res  *http.Response
		err  error
		done bool
	)

	done = false
	for i := 0; i < 3 && !done; i++ {
		func() {
			defer time.Sleep(time.Second * 3)

			res, err = responseRedirection(res)
			if err != nil {
				fmt.Println(err)
				return
			}

			res, err = parseRedirectionAndResponseIndex(res)
			if err != nil {
				fmt.Println(err)
				done = true
				return
			}

			res, err = parseIndexAndResponseAuth(res)
			if err != nil {
				fmt.Println(err)
				return
			}

			res, err = parseAuthAndResponseIssue(res)
			if err != nil {
				fmt.Println(err)
				return
			}
			defer res.Body.Close()

			result := Result{}
			dec := json.NewDecoder(res.Body)
			if err := dec.Decode(&result); err != nil {
				fmt.Println(err)
				return
			}

			if result.CD != "0000" {
				fmt.Println("wrong request:", result.CD)
				return
			} else {
				fmt.Println("connect success:", result.CD)
				done = true
				return
			}
		}()
	}
}
