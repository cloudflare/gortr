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

	InitSerial = flag.Bool("serial", false, "Send serial query instead of reset")
	Serial     = flag.Int("serial.value", 0, "Serial number")

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
	PrimaryRTRSession      = flag.Int("primary.rtr.session", 0, "Session ID")

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
	SecondaryRTRSession      = flag.Int("secondary.rtr.session", 0, "Session ID")

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
)

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

	InitSerial bool
	Serial     uint32
	SessionID  uint16

	FetchConfig *utils.FetchConfig

	Path            string
	RefreshInterval time.Duration

	qrtr chan bool

	lastUpdate time.Time

	compLock    *sync.RWMutex
	roas        map[string]*ROAJsonSimple
	compRtrLock *sync.RWMutex
	roasRtr     map[string]*ROAJsonSimple

	ch chan int
	id int
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
	waitTime := c.RefreshInterval

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
			case <-time.After(waitTime):
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
					log.Infof("Connected to server %v via ssh. Fingerprint: %v", remote.String(), serverKeyHash)
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
				log.Fatalf("Auth type %v unknown", c.SSHAuth)
			}

			log.Infof("Connecting with %v to %v", connType, rtrAddr)

			c.qrtr = make(chan bool)

			err := clientSession.Start(rtrAddr, typeToId[connType], configTLS, configSSH)
			if err != nil {
				log.Fatal(err)
			}

			go c.continuousRTR(clientSession)

			select {
			case <-c.qrtr:
				log.Info("Quitting RTR session")
			}
		} else {
			log.Infof("Fetching %s", c.Path)
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
			log.Debugf("TEST %v", decoded)

			tmpRoaMap := make(map[string]*ROAJsonSimple)
			for _, roa := range decoded.Data {
				asn, err := roa.GetASN2()
				if err != nil {
					log.Errorf("exploration error for %v asn: %v", roa, err)
					continue
				}
				prefix, err := roa.GetPrefix2()
				if err != nil {
					log.Errorf("exploration error for %v prefix: %v", roa, err)
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
		c.roasRtr[key] = &roa
		c.compRtrLock.Unlock()
	case *rtr.PDUIPv6Prefix:
		roa := ROAJsonSimple{
			Prefix: pdu.Prefix.String(),
			ASN:    pdu.ASN,
			Length: pdu.MaxLen,
		}

		key := fmt.Sprintf("%s-%d-%d", pdu.Prefix.String(), pdu.MaxLen, pdu.ASN)
		c.compRtrLock.Lock()
		c.roasRtr[key] = &roa
		c.compRtrLock.Unlock()
	case *rtr.PDUEndOfData:
		//t := time.Now().UTC().UnixNano() / 1000000000
		/*c.Data.Metadata.Generated = int(t)
		c.Data.Metadata.Valid = int(t) + int(pdu.RefreshInterval)
		c.Data.Metadata.Serial = int(pdu.SerialNumber)*/
		//cs.Disconnect()
		log.Infof("Received: %v", pdu)

		c.compRtrLock.Lock()
		tmpRoaMap := make(map[string]*ROAJsonSimple, len(c.roasRtr))
		for key, roa := range c.roasRtr {
			tmpRoaMap[key] = roa
		}
		c.compRtrLock.Unlock()

		c.compLock.Lock()
		c.roas = tmpRoaMap
		c.compLock.Unlock()

		if c.ch != nil {
			c.ch <- c.id
		}

		if c.BreakRTR {
			cs.Disconnect()
		}
	case *rtr.PDUCacheResponse:
		log.Infof("Received: %v", pdu)
	default:
		log.Infof("Received: %v", pdu)
		cs.Disconnect()
	}
}

func (c *Client) ClientConnected(cs *rtr.ClientSession) {
	if c.InitSerial {
		cs.SendSerialQuery(c.SessionID, c.Serial)
	} else {
		cs.SendResetQuery()
	}
}

func (c *Client) ClientDisconnected(cs *rtr.ClientSession) {
	log.Warn("RTR client disconnected")
	select {
	case <-c.qrtr:
	default:
		close(c.qrtr)
	}
}

func (c *Client) continuousRTR(cs *rtr.ClientSession) {
	var stop bool
	for !stop {
		select {
		case <-c.qrtr:
			stop = true
		case <-time.After():
			cs.SendSerialQuery(c.SessionID, c.Serial)
		}
	}
}

type Comparator struct {
	PrimaryClient, SecondaryClient *Client

	q    chan bool
	comp chan int

	OneOff bool

	diffLock         *sync.RWMutex
	onlyIn1, onlyIn2 []*ROAJsonSimple
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
	LastFetch int64
	URL       string
	Serial    int
}

type ROAJsonSimple struct {
	ASN    uint32 `json:"asn"`
	Length uint8  `json:"max-length"`
	Prefix string `json:"prefix"`
}

type diffExport struct {
	MetadataPrimary   int              `json:"metadata-primary"`
	MetadataSecondary int              `json:"metadata-secondary"`
	OnlyInPrimary     []*ROAJsonSimple `json:"only-primary"`
	OnlyInSecondary   []*ROAJsonSimple `json:"only-secondary"`
}

func (c *Comparator) ServeDiff(wr http.ResponseWriter, req *http.Request) {
	enc := json.NewEncoder(wr)

	c.diffLock.RLock()
	d1 := c.onlyIn1
	d2 := c.onlyIn2
	c.diffLock.RUnlock()
	export := diffExport{
		OnlyInPrimary:   d1,
		OnlyInSecondary: d2,
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
			log.Infof("Worker %d finished", id)

			c.PrimaryClient.compLock.Lock()
			roas1 := c.PrimaryClient.roas
			c.PrimaryClient.compLock.Unlock()

			c.SecondaryClient.compLock.Lock()
			roas2 := c.SecondaryClient.roas
			c.SecondaryClient.compLock.Unlock()

			onlyIn1 := Diff(roas1, roas2)
			onlyIn2 := Diff(roas2, roas1)

			c.diffLock.Lock()
			c.onlyIn1 = onlyIn1
			c.onlyIn2 = onlyIn2
			c.diffLock.Unlock()

			if id == 1 {
				donePrimary = true
			} else if id == 2 {
				doneSecondary = true
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
	c1.InitSerial = *InitSerial
	c1.Serial = uint32(*Serial)
	c1.SessionID = uint16(*PrimaryRTRSession)
	c1.SSHAuth = *PrimarySSHAuth
	c1.Path = *PrimaryHost
	c1.RefreshInterval = *PrimaryRefresh
	c1.FetchConfig = fc
	c1.BreakRTR = *PrimaryRTRBreak

	c2 := NewClient()
	c2.InitSerial = *InitSerial
	c2.Serial = uint32(*Serial)
	c2.SessionID = uint16(*SecondaryRTRSession)
	c2.SSHAuth = *SecondarySSHAuth
	c2.Path = *SecondaryHost
	c2.RefreshInterval = *SecondaryRefresh
	c2.FetchConfig = fc
	c2.BreakRTR = *SecondaryRTRBreak

	cmp := NewComparator(c1, c2)

	go func() {
		http.HandleFunc(fmt.Sprintf("/%s", *OutFile), cmp.ServeDiff)
		//	http.Handle(*MetricsPath, promhttp.Handler())

		log.Fatal(http.ListenAndServe(*Addr, nil))
	}()

	log.Fatal(cmp.Start())

}
