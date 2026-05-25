package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	return nil, fmt.Errorf("teamserver %s: %s", resp.Status, strings.TrimSpace(string(body)))
}

func (c *Client) getJSON(route string, out interface{}) error {
	req, err := http.NewRequest(http.MethodGet, c.url(route), nil)
	if err != nil {
		return err
	}
	return c.decodeJSON(req, out)
}

func (c *Client) postJSON(route string, in interface{}, out interface{}) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.url(route), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.decodeJSON(req, out)
}

func (c *Client) postMultipart(route string, fields map[string]string, out interface{}) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.url(route), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return c.decodeJSON(req, out)
}

func (c *Client) deleteJSON(route string, out interface{}) error {
	req, err := http.NewRequest(http.MethodDelete, c.url(route), nil)
	if err != nil {
		return err
	}
	return c.decodeJSON(req, out)
}

func (c *Client) decodeJSON(req *http.Request, out interface{}) error {
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) url(route string) string {
	if c.baseURL == "" {
		return route
	}
	if strings.HasPrefix(route, "?") {
		return c.baseURL + route
	}
	return c.baseURL + "/" + strings.TrimLeft(route, "/")
}

func resultRoute(beaconID uint32, since int64) string {
	route := path.Join("/api/results", strconv.FormatUint(uint64(beaconID), 10))
	if since > 0 {
		values := url.Values{}
		values.Set("since", strconv.FormatInt(since, 10))
		route += "?" + values.Encode()
	}
	return route
}

func joinCommandArgs(command string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	if command != "" {
		parts = append(parts, command)
	}
	parts = append(parts, args...)
	return joinArgs(parts)
}

func joinArgs(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, quoteArg(arg))
	}
	return strings.Join(quoted, " ")
}

func quoteArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.ContainsAny(arg, " \t\r\n\"") {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	backslashes := 0
	for _, r := range arg {
		if r == '\\' {
			backslashes++
			continue
		}
		if r == '"' {
			b.WriteString(strings.Repeat(`\`, backslashes*2+1))
			b.WriteRune(r)
			backslashes = 0
			continue
		}
		if backslashes > 0 {
			b.WriteString(strings.Repeat(`\`, backslashes))
			backslashes = 0
		}
		b.WriteRune(r)
	}
	if backslashes > 0 {
		b.WriteString(strings.Repeat(`\`, backslashes*2))
	}
	b.WriteByte('"')
	return b.String()
}
