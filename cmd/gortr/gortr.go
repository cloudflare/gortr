package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	rtr "github.com/cloudflare/gortr/lib"
	"github.com/cloudflare/gortr/prefixfile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ENV_SSH_PASSWORD = "GORTR_SSH_PASSWORD"
	ENV_SSH_KEY      = "GORTR_SSH_AUTHORIZEDKEYS"

	METHOD_NONE = iota
	METHOD_PASSWORD
	METHOD_KEY
)

var (
	version    = ""
	buildinfos = ""
	AppVersion = "GoRTR " + version + " " + buildinfos

	MetricsAddr = flag.String("metrics.addr", ":8080", "Metrics address")
	MetricsPath = flag.String("metrics.path", "/metrics", "Metrics path")

	ExportPath = flag.String("export.path", "/rpki.json", "Export path")
	ExportSign = flag.String("export.sign", "", "Sign export with key")

	RTRVersion = flag.Int("protocol", 1, "RTR protocol version")
	SessionID  = flag.Int("rtr.sessionid", -1, "Set session ID (if < 0: will be randomized)")
	RefreshRTR = flag.Int("rtr.refresh", 3600, "Refresh interval")
	RetryRTR   = flag.Int("rtr.retry", 600, "Retry interval")
	ExpireRTR  = flag.Int("rtr.expire", 7200, "Expire interval")

	Bind = flag.String("bind", ":8282", "Bind address")

	BindTLS = flag.String("tls.bind", "", "Bind address for TLS")
	TLSCert = flag.String("tls.cert", "", "Certificate path")
	TLSKey  = flag.String("tls.key", "", "Private key path")

	BindSSH = flag.String("ssh.bind", "", "Bind address for SSH")
	SSHKey  = flag.String("ssh.key", "private.pem", "SSH host key")

	SSHAuthEnablePassword = flag.Bool("ssh.method.password", false, "Enable password auth")
	SSHAuthUser           = flag.String("ssh.auth.user", "rpki", "SSH user")
	SSHAuthPassword       = flag.String("ssh.auth.password", "", fmt.Sprintf("SSH password (if blank, will use envvar %v)", ENV_SSH_PASSWORD))

	SSHAuthEnableKey  = flag.Bool("ssh.method.key", false, "Enable key auth")
	SSHAuthKeysBypass = flag.Bool("ssh.auth.key.bypass", false, "Accept any SSH key")
	SSHAuthKeysList   = flag.String("ssh.auth.key.file", "", fmt.Sprintf("Authorized SSH key file (if blank, will use envvar %v", ENV_SSH_KEY))

	TimeCheck = flag.Bool("checktime", true, "Check if file is still valid")
	Verify    = flag.Bool("verify", true, "Check signature using provided public key (disable by passing -verify=false)")
	PublicKey = flag.String("verify.key", "cf.pub", "Public key path (PEM file)")

	CacheBin        = flag.String("cache", "https://rpki.cloudflare.com/rpki.json", "URL of the cached JSON data")
	Etag            = flag.Bool("etag", true, "Enable Etag header")
	UserAgent       = flag.String("useragent", fmt.Sprintf("Cloudflare-%v (+https://github.com/cloudflare/gortr)", AppVersion), "User-Agent header")
	RefreshInterval = flag.Int("refresh", 600, "Refresh interval in seconds")
	MaxConn         = flag.Int("maxconn", 0, "Max simultaneous connections (0 to disable limit)")
	SendNotifs      = flag.Bool("notifications", true, "Send notifications to clients")

	Slurm        = flag.String("slurm", "", "Slurm configuration file (filters and assertions)")
	SlurmRefresh = flag.Bool("slurm.refresh", true, "Refresh along the cache")

	LogLevel = flag.String("loglevel", "info", "Log level")
	Version  = flag.Bool("version", false, "Print version")

	NumberOfROAs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_roas",
			Help: "Number of ROAS.",
		},
		[]string{"ip_version", "filtered", "path"},
	)
	LastRefresh = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_refresh",
			Help: "Last successfull request for the given URL.",
		},
		[]string{"path"},
	)
	LastChange = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_change",
			Help: "Last change.",
		},
		[]string{"path"},
	)
	RefreshStatusCode = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "refresh_requests_total",
			Help: "Total number of HTTP requests by status code",
		},
		[]string{"path", "code"},
	)
	ClientsMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtr_clients",
			Help: "Number of clients connected.",
		},
		[]string{"bind"},
	)
	PDUsRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rtr_pdus",
			Help: "PDU received.",
		},
		[]string{"type"},
	)

	protoverToLib = map[int]uint8{
		0: rtr.PROTOCOL_VERSION_0,
		1: rtr.PROTOCOL_VERSION_1,
	}
	authToId = map[string]int{
		"none":     METHOD_NONE,
		"password": METHOD_PASSWORD,
		//"key":   METHOD_KEY,
	}
)

func initMetrics() {
	prometheus.MustRegister(NumberOfROAs)
	prometheus.MustRegister(LastChange)
	prometheus.MustRegister(LastRefresh)
	prometheus.MustRegister(RefreshStatusCode)
	prometheus.MustRegister(ClientsMetric)
	prometheus.MustRegister(PDUsRecv)
}

func metricHTTP() {
	http.Handle(*MetricsPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(*MetricsAddr, nil))
}

func (s *state) fetchFile(file string) ([]byte, error) {
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
		tr.ProxyConnectHeader.Set("User-Agent", s.userAgent)

		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("GET", file, nil)
		req.Header.Set("User-Agent", s.userAgent)
		req.Header.Set("Accept", "text/json")

		etag, ok := s.etags[file]
		if s.enableEtags && ok {
			req.Header.Set("If-None-Match", etag)
		}

		proxyurl, err := http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, err
		}
		proxyreq := http.ProxyURL(proxyurl)
		tr.Proxy = proxyreq

		if err != nil {
			return nil, err
		}

		fhttp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", fhttp.StatusCode)).Inc()

		if fhttp.StatusCode == 304 {
			LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))
			return nil, HttpNotModified{
				File: file,
			}
		} else if fhttp.StatusCode != 200 {
			delete(s.etags, file)
			return nil, fmt.Errorf("HTTP %s", fhttp.Status)
		}
		LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))

		f = fhttp.Body

		newEtag := fhttp.Header.Get("ETag")

		if !s.enableEtags || newEtag == "" || newEtag != s.etags[file] {
			s.etags[file] = newEtag
		} else {
			return nil, IdenticalEtag{
				File: file,
				Etag: newEtag,
			}
		}
	} else {
		f, err = os.Open(file)
		if err != nil {
			return nil, err
		}
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func checkFile(data []byte) ([]byte, error) {
	hsum := sha256.Sum256(data)
	return hsum[:], nil
}

func decodeJSON(data []byte) (*prefixfile.ROAList, error) {
	buf := bytes.NewBuffer(data)
	dec := json.NewDecoder(buf)

	var roalistjson prefixfile.ROAList
	err := dec.Decode(&roalistjson)
	return &roalistjson, err
}

func processData(roalistjson []prefixfile.ROAJson) ([]rtr.ROA, int, int, int) {
	filterDuplicates := make(map[string]bool)

	roalist := make([]rtr.ROA, 0)

	var count int
	var countv4 int
	var countv6 int
	for _, v := range roalistjson {
		prefix, err := v.GetPrefix2()
		if err != nil {
			log.Error(err)
			continue
		}
		asn, err := v.GetASN2()
		if err != nil {
			log.Error(err)
			continue
		}

		count++
		if prefix.IP.To4() != nil {
			countv4++
		} else if prefix.IP.To16() != nil {
			countv6++
		}

		key := fmt.Sprintf("%s,%d,%d", prefix, asn, v.Length)
		_, exists := filterDuplicates[key]
		if !exists {
			filterDuplicates[key] = true
		} else {
			continue
		}

		roa := rtr.ROA{
			Prefix: *prefix,
			ASN:    asn,
			MaxLen: v.Length,
		}
		roalist = append(roalist, roa)
	}
	return roalist, count, countv4, countv6
}

type IdenticalFile struct {
	File string
}

func (e IdenticalFile) Error() string {
	return fmt.Sprintf("File %s is identical to the previous version", e.File)
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

func (s *state) updateFile(file string) error {
	log.Debugf("Refreshing cache from %s", file)

	s.lastts = time.Now().UTC()
	data, err := s.fetchFile(file)
	if err != nil {
		return err
	}
	hsum, _ := checkFile(data)
	if s.lasthash != nil {
		cres := bytes.Compare(s.lasthash, hsum)
		if cres == 0 {
			return IdenticalFile{File: file}
		}
	}

	s.lastchange = time.Now().UTC()
	s.lastdata = data

	roalistjson, err := decodeJSON(s.lastdata)
	if err != nil {
		return err
	}

	if s.checktime {
		validtime := time.Unix(int64(roalistjson.Metadata.Valid), 0).UTC()
		if time.Now().UTC().After(validtime) {
			return errors.New(fmt.Sprintf("File is expired: %v", validtime))
		}
	}
	if s.verify {
		log.Debugf("Verifying signature in %v", file)
		if roalistjson.Metadata.SignatureDate == "" || roalistjson.Metadata.Signature == "" {
			return errors.New("No signatures in file")
		}

		validdata, validdatatime, err := roalistjson.CheckFile(s.pubkey)
		if err != nil {
			return err
		}
		if !(validdata && (validdatatime || !s.checktime)) {
			return errors.New("Invalid signatures")
		}
		log.Debugf("Signature verified")
	}

	roasjson := roalistjson.Data
	if s.slurm != nil {
		kept, removed := s.slurm.FilterOnROAs(roasjson)
		asserted := s.slurm.AssertROAs()
		log.Infof("Slurm filtering: %v kept, %v removed, %v asserted", len(kept), len(removed), len(asserted))
		roasjson = append(kept, asserted...)
	}
	s.lockJson.Lock()
	s.exported = prefixfile.ROAList{
		Metadata: prefixfile.MetaData{
			Counts:    len(roasjson),
			Generated: roalistjson.Metadata.Generated,
			Valid:     roalistjson.Metadata.Valid,
			/*Signature:     roalistjson.Metadata.Signature,
			SignatureDate: roalistjson.Metadata.SignatureDate,*/
		},
		Data: roasjson,
	}

	if s.key != nil {
		signdate, sign, err := s.exported.Sign(s.key)
		if err != nil {
			log.Error(err)
		}
		s.exported.Metadata.Signature = sign
		s.exported.Metadata.SignatureDate = signdate
	}

	s.lockJson.Unlock()

	roas, count, countv4, countv6 := processData(roasjson)
	if err != nil {
		return err
	}

	log.Infof("New update (%v uniques, %v total prefixes). %v bytes. Updating sha256 hash %x -> %x",
		len(roas), count, len(s.lastconverted), s.lasthash, hsum)
	s.lasthash = hsum

	s.server.AddROAs(roas)

	sessid, _ := s.server.GetSessionId(nil)
	serial, _ := s.server.GetCurrentSerial(sessid)
	log.Infof("Updated added, new serial %v", serial)
	if s.sendNotifs {
		log.Debugf("Sending notifications to clients")
		s.server.NotifyClientsLatest()
	}

	if s.metricsEvent != nil {
		var countv4_dup int
		var countv6_dup int
		for _, roa := range roas {
			if roa.Prefix.IP.To4() != nil {
				countv4_dup++
			} else if roa.Prefix.IP.To16() != nil {
				countv6_dup++
			}
		}
		s.metricsEvent.UpdateMetrics(countv4, countv6, countv4_dup, countv6_dup, s.lastchange, s.lastts, file)
	}
	return nil
}

func (s *state) updateSlurm(file string) error {
	log.Debugf("Refreshing slurm from %v", file)
	data, err := s.fetchFile(file)
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(data)

	slurm, err := prefixfile.DecodeJSONSlurm(buf)
	if err != nil {
		return err
	}
	s.slurm = slurm
	return nil
}

func (s *state) routineUpdate(file string, interval int, slurmFile string) {
	log.Debugf("Starting refresh routine (file: %v, interval: %vs, slurm: %v)", file, interval, slurmFile)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	for {
		delay := time.NewTimer(time.Duration(interval) * time.Second)
		select {
		case <-delay.C:
		case <-signals:
			log.Debug("Received HUP signal")
		}
		delay.Stop()
		if slurmFile != "" {
			err := s.updateSlurm(slurmFile)
			if err != nil {
				switch err.(type) {
				case HttpNotModified:
					log.Info(err)
				case IdenticalEtag:
					log.Info(err)
				default:
					log.Errorf("Slurm: %v", err)
				}
			}
		}
		err := s.updateFile(file)
		if err != nil {
			switch err.(type) {
			case HttpNotModified:
				log.Info(err)
			case IdenticalEtag:
				log.Info(err)
			case IdenticalFile:
				log.Info(err)
			default:
				log.Errorf("Error updating: %v", err)
			}
		}
	}
}

func (s *state) exporter(wr http.ResponseWriter, r *http.Request) {
	s.lockJson.RLock()
	toExport := s.exported
	s.lockJson.RUnlock()
	enc := json.NewEncoder(wr)
	enc.Encode(toExport)
}

type state struct {
	lastdata      []byte
	lastconverted []byte
	lasthash      []byte
	lastchange    time.Time
	lastts        time.Time
	sendNotifs    bool
	userAgent     string
	etags         map[string]string
	enableEtags   bool

	server *rtr.Server

	metricsEvent *metricsEvent

	exported prefixfile.ROAList
	lockJson *sync.RWMutex
	key      *ecdsa.PrivateKey

	slurm *prefixfile.SlurmConfig

	pubkey    *ecdsa.PublicKey
	verify    bool
	checktime bool
}

type metricsEvent struct {
}

func (m *metricsEvent) ClientConnected(c *rtr.Client) {
	ClientsMetric.WithLabelValues(c.GetLocalAddress().String()).Inc()
}

func (m *metricsEvent) ClientDisconnected(c *rtr.Client) {
	ClientsMetric.WithLabelValues(c.GetLocalAddress().String()).Dec()
}

func (m *metricsEvent) HandlePDU(c *rtr.Client, pdu rtr.PDU) {
	PDUsRecv.WithLabelValues(
		strings.ToLower(
			strings.Replace(
				rtr.TypeToString(
					pdu.GetType()),
				" ",
				"_", -1))).Inc()
}

func (m *metricsEvent) UpdateMetrics(numIPv4 int, numIPv6 int, numIPv4filtered int, numIPv6filtered int, changed time.Time, refreshed time.Time, file string) {
	NumberOfROAs.WithLabelValues("ipv4", "filtered", file).Set(float64(numIPv4filtered))
	NumberOfROAs.WithLabelValues("ipv4", "unfiltered", file).Set(float64(numIPv4))
	NumberOfROAs.WithLabelValues("ipv6", "filtered", file).Set(float64(numIPv6filtered))
	NumberOfROAs.WithLabelValues("ipv6", "unfiltered", file).Set(float64(numIPv6))
	LastChange.WithLabelValues(file).Set(float64(changed.UnixNano() / 1e9))
}

func ReadPublicKey(key []byte, isPem bool) (*ecdsa.PublicKey, error) {
	if isPem {
		block, _ := pem.Decode(key)
		key = block.Bytes
	}

	k, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	kconv, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Not EDCSA public key")
	}
	return kconv, nil
}

func ReadKey(key []byte, isPem bool) (*ecdsa.PrivateKey, error) {
	if isPem {
		block, _ := pem.Decode(key)
		key = block.Bytes
	}

	k, err := x509.ParseECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	deh := &rtr.DefaultRTREventHandler{
		Log: log.StandardLogger(),
	}

	sc := rtr.ServerConfiguration{
		ProtocolVersion: protoverToLib[*RTRVersion],
		SessId:          *SessionID,
		KeepDifference:  3,
		Log:             log.StandardLogger(),

		RefreshInterval: uint32(*RefreshRTR),
		RetryInterval:   uint32(*RetryRTR),
		ExpireInterval:  uint32(*ExpireRTR),
	}

	var me *metricsEvent
	var enableHTTP bool
	if *MetricsAddr != "" {
		initMetrics()
		me = &metricsEvent{}
		enableHTTP = true
	}

	server := rtr.NewServer(sc, me, deh)
	deh.SetROAManager(server)

	var pubkey *ecdsa.PublicKey
	if *Verify {
		pubkeyBytes, err := ioutil.ReadFile(*PublicKey)
		if err != nil {
			log.Fatal(err)
		}

		pubkey, err = ReadPublicKey(pubkeyBytes, true)
		if err != nil {
			log.Fatal(err)
		}
	}

	s := state{
		server:       server,
		metricsEvent: me,
		sendNotifs:   *SendNotifs,
		pubkey:       pubkey,
		verify:       *Verify,
		checktime:    *TimeCheck,
		userAgent:    *UserAgent,
		etags:        make(map[string]string),
		enableEtags:  *Etag,
		lockJson:     &sync.RWMutex{},
	}

	if *ExportSign != "" {
		keyFile, err := os.Open(*ExportSign)
		if err != nil {
			log.Fatal(err)
		}
		keyBytes, err := ioutil.ReadAll(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		keyFile.Close()
		keyDec, err := ReadKey(keyBytes, true)
		if err != nil {
			log.Fatal(err)
		}
		s.key = keyDec
	}

	if enableHTTP {
		if *ExportPath != "" {
			http.HandleFunc(*ExportPath, s.exporter)
		}
		go metricHTTP()
	}

	if *Bind == "" && *BindTLS == "" && *BindSSH == "" {
		log.Fatalf("Specify at least a bind address")
	}

	if *Bind != "" {
		go func() {
			sessid, _ := server.GetSessionId(nil)
			log.Infof("GoRTR Server started (sessionID:%d, refresh:%d, retry:%d, expire:%d)", sessid, sc.RefreshInterval, sc.RetryInterval, sc.ExpireInterval)
			err := server.Start(*Bind)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}
	if *BindTLS != "" {
		cert, err := tls.LoadX509KeyPair(*TLSCert, *TLSKey)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		go func() {
			err := server.StartTLS(*BindTLS, &tlsConfig)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}
	if *BindSSH != "" {
		sshkey, err := ioutil.ReadFile(*SSHKey)
		if err != nil {
			log.Fatal(err)
		}
		private, err := ssh.ParsePrivateKey(sshkey)
		if err != nil {
			log.Fatal("Failed to parse private key: ", err)
		}

		sshConfig := ssh.ServerConfig{}

		log.Infof("Enabling ssh with the following authentications: password=%v, key=%v", *SSHAuthEnablePassword, *SSHAuthEnableKey)
		if *SSHAuthEnablePassword {
			password := *SSHAuthPassword
			if password == "" {
				password = os.Getenv(ENV_SSH_PASSWORD)
			}
			sshConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				log.Infof("Connected (ssh-password): %v/%v", conn.User(), conn.RemoteAddr())
				if conn.User() != *SSHAuthUser || !bytes.Equal(password, []byte(*SSHAuthPassword)) {
					log.Warnf("Wrong user or password for %v/%v. Disconnecting.", conn.User(), conn.RemoteAddr())
					return nil, errors.New("Wrong user or password")
				}

				return &ssh.Permissions{
					CriticalOptions: make(map[string]string),
					Extensions:      make(map[string]string),
				}, nil
			}
		}
		if *SSHAuthEnableKey {
			var sshClientKeysToDecode string
			if *SSHAuthKeysList == "" {
				sshClientKeysToDecode = os.Getenv(ENV_SSH_KEY)
			} else {
				sshClientKeysToDecodeBytes, err := ioutil.ReadFile(*SSHAuthKeysList)
				if err != nil {
					log.Fatal(err)
				}
				sshClientKeysToDecode = string(sshClientKeysToDecodeBytes)
			}
			sshClientKeys := strings.Split(sshClientKeysToDecode, "\n")

			sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				keyBase64 := base64.RawStdEncoding.EncodeToString(key.Marshal())
				if !*SSHAuthKeysBypass {
					var noKeys bool
					for i, k := range sshClientKeys {
						if k == "" {
							continue
						}
						if strings.HasPrefix(fmt.Sprintf("%v %v", key.Type(), keyBase64), k) {
							log.Infof("Connected (ssh-key): %v/%v with key %v %v (matched with line %v)",
								conn.User(), conn.RemoteAddr(), key.Type(), keyBase64, i+1)
							noKeys = true
							break
						}
					}
					if !noKeys {
						log.Warnf("No key for %v/%v %v %v. Disconnecting.", conn.User(), conn.RemoteAddr(), key.Type(), keyBase64)
						return nil, errors.New("Key not found")
					}
				} else {
					log.Infof("Connected (ssh-key): %v/%v with key %v %v", conn.User(), conn.RemoteAddr(), key.Type(), keyBase64)
				}

				return &ssh.Permissions{
					CriticalOptions: make(map[string]string),
					Extensions:      make(map[string]string),
				}, nil
			}
		}

		if !(*SSHAuthEnableKey || *SSHAuthEnablePassword) {
			sshConfig.NoClientAuth = true
		}

		sshConfig.AddHostKey(private)
		go func() {
			err := server.StartSSH(*BindSSH, &sshConfig)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	slurmFile := *Slurm
	if slurmFile != "" {
		err := s.updateSlurm(slurmFile)
		if err != nil {
			switch err.(type) {
			case HttpNotModified:
				log.Info(err)
			case IdenticalEtag:
				log.Info(err)
			default:
				log.Errorf("Slurm: %v", err)
			}
		}
		if !*SlurmRefresh {
			slurmFile = ""
		}
	}

	err := s.updateFile(*CacheBin)
	if err != nil {
		switch err.(type) {
		case HttpNotModified:
			log.Info(err)
		case IdenticalFile:
			log.Info(err)
		case IdenticalEtag:
			log.Info(err)
		default:
			log.Errorf("Error updating: %v", err)
		}
	}
	s.routineUpdate(*CacheBin, *RefreshInterval, slurmFile)

}
