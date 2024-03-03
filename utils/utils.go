package utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type FetchConfig struct {
	UserAgent string
	Mime      string

	etags       map[string]string
	etagsLock   *sync.RWMutex
	EnableEtags bool
}

func NewFetchConfig() *FetchConfig {
	return &FetchConfig{
		etags:     make(map[string]string),
		etagsLock: &sync.RWMutex{},
		Mime:      "application/json",
	}
}

type HttpNotModified struct {
	File string
}

func (e HttpNotModified) Error() string {
	return fmt.Sprintf("HTTP 304 Not modified for %s", e.File)
}

type IdenticalEtag struct {
	File string
	Etag string
}

func (e IdenticalEtag) Error() string {
	return fmt.Sprintf("File %s is identical according to Etag: %s", e.File, e.Etag)
}

func (c *FetchConfig) FetchFile(file string) ([]byte, int, error) {
	var f io.Reader
	var err error

	status_code := -1

	if len(file) > 8 && (file[0:7] == "http://" || file[0:8] == "https://") {
		// Copying base of DefaultTransport from https://golang.org/src/net/http/transport.go
		// There is a proposal for a Clone of
		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ProxyConnectHeader:    map[string][]string{},
		}

		// Keep User-Agent in proxy request
		tr.ProxyConnectHeader.Set("User-Agent", c.UserAgent)

		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("GET", file, nil)
		if err != nil {
			return nil, -1, err
		}
		req.Header.Set("User-Agent", c.UserAgent)
		if c.Mime != "" {
			req.Header.Set("Accept", c.Mime)
		}

		c.etagsLock.RLock()
		etag, ok := c.etags[file]
		c.etagsLock.RUnlock()
		if c.EnableEtags && ok {
			req.Header.Set("If-None-Match", etag)
		}

		proxyurl, err := http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, -1, err
		}
		proxyreq := http.ProxyURL(proxyurl)
		tr.Proxy = proxyreq

		fhttp, err := client.Do(req)
		if err != nil {
			return nil, -1, err
		}
		if fhttp.Body != nil {
			defer fhttp.Body.Close()
		}
		defer client.CloseIdleConnections()

		if fhttp.StatusCode == 304 {
			return nil, fhttp.StatusCode, HttpNotModified{
				File: file,
			}
		}

		if fhttp.StatusCode != 200 {
			c.etagsLock.Lock()
			delete(c.etags, file)
			c.etagsLock.Unlock()
		}

		newEtag := fhttp.Header.Get("ETag")
		if c.EnableEtags && newEtag != "" && newEtag == c.etags[file] {
			return nil, fhttp.StatusCode, IdenticalEtag{
				File: file,
				Etag: newEtag,
			}
		}

		c.etagsLock.Lock()
		c.etags[file] = newEtag
		c.etagsLock.Unlock()

		f = fhttp.Body
		status_code = fhttp.StatusCode
	} else {
		f, err = os.Open(file)
		if err != nil {
			return nil, -1, err
		}
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, -1, err
	}

	return data, status_code, nil
}
