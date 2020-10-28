package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	rtr "github.com/cloudflare/gortr/lib"
	"github.com/cloudflare/gortr/prefixfile"
	"github.com/cloudflare/gortr/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"
)

const (
	version    = ""
	buildinfos = ""
	AppVersion = "RTRmon " + version + " " + buildinfos

	ENV_SSH_PASSWORD = "RTR_SSH_PASSWORD"
	ENV_SSH_KEY      = "RTR_SSH_KEY"

	METHOD_NONE = iota
	METHOD_PASSWORD
	METHOD_KEY
)

var (
	OneOff      = flag.Bool("oneoff", false, "dump as json and exits")
	Addr        = flag.String("addr", ":8080", "Server address")
	MetricsPath = flag.String("metrics", "/metrics", "Metrics path")
	OutFile     = flag.String("file", "diff.json", "Diff file (or URL path without /)")

	UserAgent = flag.String("useragent", fmt.Sprintf("Cloudflare-%v (+https://github.com/cloudflare/gortr)", AppVersion), "User-Agent header")

	PrimaryHost            = flag.String("primary.host", "tcp://rtr.rpki.cloudflare.com:8282", "primary server")
	PrimaryValidateCert    = flag.Bool("primary.tls.validate", true, "Validate TLS")
	PrimaryValidateSSH     = flag.Bool("primary.ssh.validate", false, "Validate SSH key")
	PrimarySSHServerKey    = flag.String("primary.ssh.validate.key", "", "SSH server key SHA256 to validate")
	PrimarySSHAuth         = flag.String("primary.ssh.method", "none", "Select SSH method (none, password or key)")
	PrimarySSHAuthUser     = flag.String("primary.ssh.auth.user", "rpki", "SSH user")
	PrimarySSHAuthPassword = flag.String("primary.ssh.auth.password", "", fmt.Sprintf("SSH password (if blank, will use envvar %s_1)", ENV_SSH_PASSWORD))
	PrimarySSHAuthKey      = flag.String("primary.ssh.auth.key", "id_rsa", fmt.Sprintf("SSH key file (if blank, will use envvar %s_1)", ENV_SSH_KEY))
	PrimaryRefresh         = flag.Duration("primary.refresh", time.Second*600, "Refresh interval")
	PrimaryRTRBreak        = flag.Bool("primary.rtr.break", false, "Break RTR session at each interval")

	SecondaryHost            = flag.String("secondary.host", "https://rpki.cloudflare.com/rpki.json", "secondary server")
	SecondaryValidateCert    = flag.Bool("secondary.tls.validate", true, "Validate TLS")
	SecondaryValidateSSH     = flag.Bool("secondary.ssh.validate", false, "Validate SSH key")
	SecondarySSHServerKey    = flag.String("secondary.ssh.validate.key", "", "SSH server key SHA256 to validate")
	SecondarySSHAuth         = flag.String("secondary.ssh.method", "none", "Select SSH method (none, password or key)")
	SecondarySSHAuthUser     = flag.String("secondary.ssh.auth.user", "rpki", "SSH user")
	SecondarySSHAuthPassword = flag.String("secondary.ssh.auth.password", "", fmt.Sprintf("SSH password (if blank, will use envvar %s_2)", ENV_SSH_PASSWORD))
	SecondarySSHAuthKey      = flag.String("secondary.ssh.auth.key", "id_rsa", fmt.Sprintf("SSH key file (if blank, will use envvar %s_2)", ENV_SSH_KEY))
	SecondaryRefresh         = flag.Duration("secondary.refresh", time.Second*600, "Refresh interval")
	SecondaryRTRBreak        = flag.Bool("secondary.rtr.break", false, "Break RTR session at each interval")

	LogLevel = flag.String("loglevel", "info", "Log level")
	Version  = flag.Bool("version", false, "Print version")

	typeToId = map[string]int{
		"tcp": rtr.TYPE_PLAIN,
		"tls": rtr.TYPE_TLS,
		"ssh": rtr.TYPE_SSH,
	}
	authToId = map[string]int{
		"none":     METHOD_NONE,
		"password": METHOD_PASSWORD,
		"key":      METHOD_KEY,
	}

	ROACount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_roas",
			Help: "Total number of ROAS/amount of differents.",
		},
		[]string{"server", "url", "type"},
	)
	RTRState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtr_state",
			Help: "State of the RTR session (up/down).",
		},
		[]string{"server", "url"},
	)
	RTRSerial = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtr_serial",
			Help: "Serial of the RTR session.",
		},
		[]string{"server", "url"},
	)
	RTRSession = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtr_session",
			Help: "ID of the RTR session.",
		},
		[]string{"server", "url"},
	)
	LastUpdate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "update",
			Help: "Timestamp of last update.",
		},
		[]string{"server", "url"},
	)

	idToInfo = map[int]string{
		0: "unknown",
		1: "primary",
		2: "secondary",
	}
)

func init() {
	prometheus.MustRegister(ROACount)
	prometheus.MustRegister(RTRState)
	prometheus.MustRegister(RTRSerial)
	prometheus.MustRegister(RTRSession)
	prometheus.MustRegister(LastUpdate)
}

func decodeJSON(data []byte) (*prefixfile.ROAList, error) {
	buf := bytes.NewBuffer(data)
	dec := json.NewDecoder(buf)

	var roalistjson prefixfile.ROAList
	err := dec.Decode(&roalistjson)
	return &roalistjson, err
}

type Client struct {
	//Data prefixfile.ROAList
	ValidateSSH     bool
	ValidateCert    bool
	SSHAuthUser     string
	SSHAuthKey      string
	SSHServerKey    string
	SSHAuthPassword string
	SSHAuth         string
	BreakRTR        bool

	serial    uint32
	sessionID uint16

	FetchConfig *utils.FetchConfig

	Path            string
	RefreshInterval time.Duration

	qrtr chan bool

	lastUpdate time.Time

	compLock    *sync.RWMutex
	roas        map[string]*ROAJsonSimple
	compRtrLock *sync.RWMutex
	roasRtr     map[string]*ROAJsonSimple

	unlock chan bool
	ch     chan int
	id     int

	rtrRefresh uint32
	rtrRetry   uint32
	rtrExpire  uint32
}

func NewClient() *Client {
	return &Client{
		compLock:    &sync.RWMutex{},
		roas:        make(map[string]*ROAJsonSimple),
		compRtrLock: &sync.RWMutex{},
		roasRtr:     make(map[string]*ROAJsonSimple),
	}
}

func (c *Client) Start(id int, ch chan int) {
	c.ch = ch
	c.id = id

	pathUrl, err := url.Parse(c.Path)
	if err != nil {
		log.Fatal(err)
	}

	connType := pathUrl.Scheme
	rtrAddr := fmt.Sprintf("%s", pathUrl.Host)

	bypass := true
	for {

		if !bypass {
			select {
			case <-time.After(c.RefreshInterval):
			}
		}
		bypass = false

		if connType == "ssh" || connType == "tcp" || connType == "tls" {

			cc := rtr.ClientConfiguration{
				ProtocolVersion: rtr.PROTOCOL_VERSION_1,
				Log:             log.StandardLogger(),
			}

			clientSession := rtr.NewClientSession(cc, c)

			configTLS := &tls.Config{
				InsecureSkipVerify: !c.ValidateCert,
			}
			configSSH := &ssh.ClientConfig{
				Auth: make([]ssh.AuthMethod, 0),
				User: c.SSHAuthUser,
				HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					serverKeyHash := ssh.FingerprintSHA256(key)
					if c.ValidateSSH {
						if serverKeyHash != fmt.Sprintf("SHA256:%v", c.SSHServerKey) {
							return errors.New(fmt.Sprintf("Server key hash %v is different than expected key hash SHA256:%v", serverKeyHash, c.SSHServerKey))
						}
					}
					log.Infof("%d: Connected to server %v via ssh. Fingerprint: %v", id, remote.String(), serverKeyHash)
					return nil
				},
			}
			if authType, ok := authToId[c.SSHAuth]; ok {
				if authType == METHOD_PASSWORD {
					password := c.SSHAuthPassword
					if password == "" {
						password = os.Getenv(ENV_SSH_PASSWORD)
					}
					configSSH.Auth = append(configSSH.Auth, ssh.Password(password))
				} else if authType == METHOD_KEY {
					var keyBytes []byte
					var err error
					if c.SSHAuthKey == "" {
						keyBytesStr := os.Getenv(ENV_SSH_KEY)
						keyBytes = []byte(keyBytesStr)
					} else {
						keyBytes, err = ioutil.ReadFile(c.SSHAuthKey)
						if err != nil {
							log.Fatal(err)
						}
					}
					signer, err := ssh.ParsePrivateKey(keyBytes)
					if err != nil {
						log.Fatal(err)
					}
					configSSH.Auth = append(configSSH.Auth, ssh.PublicKeys(signer))
				}
			} else {
				log.Fatalf("%d: Auth type %v unknown", id, c.SSHAuth)
			}

			log.Infof("%d: Connecting with %v to %v", id, connType, rtrAddr)

			c.qrtr = make(chan bool)
			c.unlock = make(chan bool)
			if !c.BreakRTR {
				go c.continuousRTR(clientSession)
			}

			err := clientSession.Start(rtrAddr, typeToId[connType], configTLS, configSSH)
			if err != nil {
				log.Fatal(err)
			}

			select {
			case <-c.qrtr:
				log.Infof("%d: Quitting RTR session", id)
			}
		} else {
			log.Infof("%d: Fetching %s", c.id, c.Path)
			data, _, _, err := c.FetchConfig.FetchFile(c.Path)
			if err != nil {
				log.Error(err)
				continue
			}
			log.Debug(data)
			decoded, err := decodeJSON(data)
			if err != nil {
				log.Error(err)
				continue
			}

			c.lastUpdate = time.Now().UTC()

			tmpRoaMap := make(map[string]*ROAJsonSimple)
			for _, roa := range decoded.Data {
				asn, err := roa.GetASN2()
				if err != nil {
					log.Errorf("%d: exploration error for %v asn: %v", id, roa, err)
					continue
				}
				prefix, err := roa.GetPrefix2()
				if err != nil {
					log.Errorf("%d: exploration error for %v prefix: %v", id, roa, err)
					continue
				}

				maxlen := roa.GetMaxLen()
				key := fmt.Sprintf("%s-%d-%d", prefix.String(), maxlen, asn)

				roaSimple := ROAJsonSimple{
					Prefix: prefix.String(),
					ASN:    asn,
					Length: uint8(maxlen),
				}
				tmpRoaMap[key] = &roaSimple
			}
			c.compLock.Lock()
			c.roas = tmpRoaMap
			c.lastUpdate = time.Now().UTC()
			c.serial = uint32(decoded.Metadata.Serial)
			c.compLock.Unlock()
			if ch != nil {
				ch <- id
			}
		}

	}

}

func (c *Client) HandlePDU(cs *rtr.ClientSession, pdu rtr.PDU) {
	switch pdu := pdu.(type) {
	case *rtr.PDUIPv4Prefix:
		roa := ROAJsonSimple{
			Prefix: pdu.Prefix.String(),
			ASN:    pdu.ASN,
			Length: pdu.MaxLen,
		}

		key := fmt.Sprintf("%s-%d-%d", pdu.Prefix.String(), pdu.MaxLen, pdu.ASN)
		c.compRtrLock.Lock()

		if pdu.Flags == rtr.FLAG_ADDED {
			c.roasRtr[key] = &roa
		} else {
			delete(c.roasRtr, key)
		}

		c.compRtrLock.Unlock()
	case *rtr.PDUIPv6Prefix:
		roa := ROAJsonSimple{
			Prefix: pdu.Prefix.String(),
			ASN:    pdu.ASN,
			Length: pdu.MaxLen,
		}

		key := fmt.Sprintf("%s-%d-%d", pdu.Prefix.String(), pdu.MaxLen, pdu.ASN)
		c.compRtrLock.Lock()

		if pdu.Flags == rtr.FLAG_ADDED {
			c.roasRtr[key] = &roa
		} else {
			delete(c.roasRtr, key)
		}

		c.compRtrLock.Unlock()
	case *rtr.PDUEndOfData:
		log.Infof("%d: Received: %v", c.id, pdu)

		c.compRtrLock.Lock()
		c.serial = pdu.SerialNumber
		tmpRoaMap := make(map[string]*ROAJsonSimple, len(c.roasRtr))
		for key, roa := range c.roasRtr {
			tmpRoaMap[key] = roa
		}
		c.compRtrLock.Unlock()

		c.compLock.Lock()
		c.roas = tmpRoaMap

		c.rtrRefresh = pdu.RefreshInterval
		c.rtrRetry = pdu.RetryInterval
		c.rtrExpire = pdu.ExpireInterval
		c.lastUpdate = time.Now().UTC()
		c.compLock.Unlock()

		if c.ch != nil {
			c.ch <- c.id
		}

		if c.BreakRTR {
			cs.Disconnect()
		}
	case *rtr.PDUCacheResponse:
		log.Infof("%d: Received: %v", c.id, pdu)
		c.sessionID = pdu.SessionId
	case *rtr.PDUCacheReset:
		log.Infof("%d: Received: %v", c.id, pdu)
	case *rtr.PDUSerialNotify:
		log.Infof("%d: Received: %v", c.id, pdu)
	default:
		log.Infof("%d: Received: %v", c.id, pdu)
		cs.Disconnect()
	}
}

func (c *Client) ClientConnected(cs *rtr.ClientSession) {
	close(c.unlock)
	cs.SendResetQuery()

	RTRState.With(
		prometheus.Labels{
			"server": idToInfo[c.id],
			"url":    c.Path,
		}).Set(float64(1))
}

func (c *Client) ClientDisconnected(cs *rtr.ClientSession) {
	log.Warnf("%d: RTR client disconnected", c.id)
	select {
	case <-c.qrtr:
	default:
		close(c.qrtr)
	}

	RTRState.With(
		prometheus.Labels{
			"server": idToInfo[c.id],
			"url":    c.Path,
		}).Set(float64(0))
}

func (c *Client) continuousRTR(cs *rtr.ClientSession) {
	log.Debugf("%d: RTR routine started", c.id)
	var stop bool

	select {
	case <-c.unlock:
	case <-c.qrtr:
		stop = true
	}

	for !stop {
		select {
		case <-c.qrtr:
			stop = true
		case <-time.After(c.RefreshInterval):
			cs.SendSerialQuery(c.sessionID, c.serial)
		}
	}
}

func (c *Client) GetData() (map[string]*ROAJsonSimple, *diffMetadata) {
	c.compLock.RLock()
	roas := c.roas

	md := &diffMetadata{
		URL:       c.Path,
		Serial:    c.serial,
		SessionID: c.sessionID,
		Count:     len(roas),

		RTRRefresh: c.rtrRefresh,
		RTRRetry:   c.rtrRetry,
		RTRExpire:  c.rtrExpire,

		LastFetch: c.lastUpdate.UnixNano() / 1e9,
	}

	c.compLock.RUnlock()

	return roas, md
}

type Comparator struct {
	PrimaryClient, SecondaryClient *Client

	q    chan bool
	comp chan int

	OneOff bool

	diffLock         *sync.RWMutex
	onlyIn1, onlyIn2 []*ROAJsonSimple
	md1              *diffMetadata
	md2              *diffMetadata
}

func NewComparator(c1, c2 *Client) *Comparator {
	return &Comparator{
		PrimaryClient:   c1,
		SecondaryClient: c2,

		q:    make(chan bool),
		comp: make(chan int),

		diffLock: &sync.RWMutex{},
	}
}

func Diff(a, b map[string]*ROAJsonSimple) []*ROAJsonSimple {
	onlyInA := make([]*ROAJsonSimple, 0)
	for key, roa := range a {
		if _, ok := b[key]; !ok {
			onlyInA = append(onlyInA, roa)
		}
	}
	return onlyInA
}

type diffMetadata struct {
	LastFetch int64  `json:"last-fetch"`
	URL       string `json:"url"`
	Serial    uint32 `json:"serial"`
	SessionID uint16 `json:"session-id"`
	Count     int    `json:"count"`

	RTRRefresh uint32 `json:"rtr-refresh"`
	RTRRetry   uint32 `json:"rtr-retry"`
	RTRExpire  uint32 `json:"rtr-expire"`
}

type ROAJsonSimple struct {
	ASN    uint32 `json:"asn"`
	Length uint8  `json:"max-length"`
	Prefix string `json:"prefix"`
}

type diffExport struct {
	MetadataPrimary   *diffMetadata    `json:"metadata-primary"`
	MetadataSecondary *diffMetadata    `json:"metadata-secondary"`
	OnlyInPrimary     []*ROAJsonSimple `json:"only-primary"`
	OnlyInSecondary   []*ROAJsonSimple `json:"only-secondary"`
}

func (c *Comparator) ServeDiff(wr http.ResponseWriter, req *http.Request) {
	enc := json.NewEncoder(wr)

	c.diffLock.RLock()
	d1 := c.onlyIn1
	d2 := c.onlyIn2

	md1 := c.md1
	md2 := c.md2
	c.diffLock.RUnlock()
	export := diffExport{
		MetadataPrimary:   md1,
		MetadataSecondary: md2,
		OnlyInPrimary:     d1,
		OnlyInSecondary:   d2,
	}

	wr.Header().Add("content-type", "application/json")

	enc.Encode(export)
}

func (c *Comparator) Compare() {
	var donePrimary, doneSecondary bool
	var stop bool
	for !stop {
		select {
		case <-c.q:
			stop = true
			continue
		case id := <-c.comp:
			log.Infof("Worker %d finished: comparison", id)

			roas1, md1 := c.PrimaryClient.GetData()
			roas2, md2 := c.SecondaryClient.GetData()

			onlyIn1 := Diff(roas1, roas2)
			onlyIn2 := Diff(roas2, roas1)

			c.diffLock.Lock()
			c.onlyIn1 = onlyIn1
			c.onlyIn2 = onlyIn2

			c.md1 = md1
			c.md2 = md2

			ROACount.With(
				prometheus.Labels{
					"server": "primary",
					"url":    md1.URL,
					"type":   "total",
				}).Set(float64(len(roas1)))

			ROACount.With(
				prometheus.Labels{
					"server": "primary",
					"url":    md1.URL,
					"type":   "diff",
				}).Set(float64(len(onlyIn1)))

			ROACount.With(
				prometheus.Labels{
					"server": "secondary",
					"url":    md1.URL,
					"type":   "total",
				}).Set(float64(len(roas2)))

			ROACount.With(
				prometheus.Labels{
					"server": "secondary",
					"url":    md1.URL,
					"type":   "diff",
				}).Set(float64(len(onlyIn2)))

			RTRSerial.With(
				prometheus.Labels{
					"server": "primary",
					"url":    md1.URL,
				}).Set(float64(md1.Serial))

			RTRSerial.With(
				prometheus.Labels{
					"server": "secondary",
					"url":    md2.URL,
				}).Set(float64(md2.Serial))

			RTRSession.With(
				prometheus.Labels{
					"server": "primary",
					"url":    md1.URL,
				}).Set(float64(md1.SessionID))

			RTRSession.With(
				prometheus.Labels{
					"server": "secondary",
					"url":    md2.URL,
				}).Set(float64(md2.SessionID))

			c.diffLock.Unlock()

			if id == 1 {
				donePrimary = true

				LastUpdate.With(
					prometheus.Labels{
						"server": "primary",
						"url":    md1.URL,
					}).Set(float64(md1.LastFetch))

			} else if id == 2 {
				doneSecondary = true

				LastUpdate.With(
					prometheus.Labels{
						"server": "secondary",
						"url":    md2.URL,
					}).Set(float64(md2.LastFetch))
			}

			if c.OneOff && donePrimary && doneSecondary {
				// save file
				stop = true
			}

		}
	}
}

func (c *Comparator) Start() error {
	if c.PrimaryClient == nil || c.SecondaryClient == nil {
		return errors.New("must have two clients")
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.PrimaryClient.Start(1, c.comp)
	}()
	go func() {
		defer wg.Done()
		c.SecondaryClient.Start(2, c.comp)
	}()

	go c.Compare()

	wg.Wait()
	close(c.q)
	return nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	//	if len(file) > 8 && (file[0:7] == "http://" || file[0:8] == "https://") {

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	fc := utils.NewFetchConfig()
	fc.UserAgent = *UserAgent

	c1 := NewClient()
	c1.SSHAuth = *PrimarySSHAuth
	c1.Path = *PrimaryHost
	c1.RefreshInterval = *PrimaryRefresh
	c1.FetchConfig = fc
	c1.BreakRTR = *PrimaryRTRBreak

	c2 := NewClient()
	c2.SSHAuth = *SecondarySSHAuth
	c2.Path = *SecondaryHost
	c2.RefreshInterval = *SecondaryRefresh
	c2.FetchConfig = fc
	c2.BreakRTR = *SecondaryRTRBreak

	cmp := NewComparator(c1, c2)

	go func() {
		http.HandleFunc(fmt.Sprintf("/%s", *OutFile), cmp.ServeDiff)
		http.Handle(*MetricsPath, promhttp.Handler())

		log.Fatal(http.ListenAndServe(*Addr, nil))
	}()

	log.Fatal(cmp.Start())

}
