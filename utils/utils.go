package utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
	"sync"
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
		etags: make(map[string]string),
		etagsLock: &sync.RWMutex{},
		Mime: "application/json",
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

func (c *FetchConfig) FetchFile(file string) ([]byte, int, bool, error) {
	var f io.Reader
	var err error
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
			return nil, -1, false, err
		}
		proxyreq := http.ProxyURL(proxyurl)
		tr.Proxy = proxyreq

		if err != nil {
			return nil, -1, false, err
		}

		fhttp, err := client.Do(req)
		if err != nil {
			return nil, -1, false, err
		}
		if fhttp.Body != nil {
			defer fhttp.Body.Close()
		}
		defer client.CloseIdleConnections()
		//RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", fhttp.StatusCode)).Inc()

		if fhttp.StatusCode == 304 {
			//LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))
			return nil, fhttp.StatusCode, true, HttpNotModified{
				File: file,
			}
		} else if fhttp.StatusCode != 200 {
			c.etagsLock.Lock()
			delete(c.etags, file)
			c.etagsLock.Unlock()
			return nil, fhttp.StatusCode, true, fmt.Errorf("HTTP %s", fhttp.Status)
		}
		//LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))

		f = fhttp.Body

		newEtag := fhttp.Header.Get("ETag")

		if !c.EnableEtags || newEtag == "" || newEtag != c.etags[file] { // check lock here
			c.etagsLock.Lock()
			c.etags[file] = newEtag
			c.etagsLock.Unlock()
		} else {
			return nil, fhttp.StatusCode, true, IdenticalEtag{
				File: file,
				Etag: newEtag,
			}
		}
	} else {
		f, err = os.Open(file)
		if err != nil {
			return nil, -1, false, err
		}
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, -1, false, err
	}
	return data, -1, false, nil
}
