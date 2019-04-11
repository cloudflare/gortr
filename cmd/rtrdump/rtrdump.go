package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	rtr "github.com/cloudflare/gortr/lib"
	"github.com/cloudflare/gortr/prefixfile"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"runtime"
	"time"
	"io/ioutil"
)

const (
	AppVersion = "RTRdump 0.11.0"

	ENV_SSH_PASSWORD = "RTR_SSH_PASSWORD"
	ENV_SSH_KEY = "RTR_SSH_KEY"

	METHOD_NONE = iota
	METHOD_PASSWORD
	METHOD_KEY
)

var (
	Connect = flag.String("connect", "127.0.0.1:8282", "Connection address")
	OutFile = flag.String("file", "output.json", "Output file")

	ConnType     = flag.String("type", "plain", "Type of connection: plain, tls or ssh")
	ValidateCert = flag.Bool("tls.validate", true, "Validate TLS")

	ValidateSSH     = flag.Bool("ssh.validate", false, "Validate SSH key")
	SSHServerKey    = flag.String("ssh.validate.key", "", "SSH server key SHA256 to validate")
	SSHAuth         = flag.String("ssh.method", "none", "Select SSH method (none, password or key)")
	SSHAuthUser     = flag.String("ssh.auth.user", "rpki", "SSH user")
	SSHAuthPassword = flag.String("ssh.auth.password", "", fmt.Sprintf("SSH password (if blank, will use envvar %v)", ENV_SSH_PASSWORD))
	SSHAuthKey = flag.String("ssh.auth.key", "id_rsa", fmt.Sprintf("SSH key file (if blank, will use envvar %v)", ENV_SSH_KEY))

	RefreshInterval = flag.Int("refresh", 600, "Refresh interval in seconds")

	LogLevel = flag.String("loglevel", "info", "Log level")
	Version  = flag.Bool("version", false, "Print version")

	typeToId = map[string]int{
		"plain": rtr.TYPE_PLAIN,
		"tls":   rtr.TYPE_TLS,
		"ssh":   rtr.TYPE_SSH,
	}
	authToId = map[string]int{
		"none":     METHOD_NONE,
		"password": METHOD_PASSWORD,
		"key":   METHOD_KEY,
	}
)

type Client struct {
	Data prefixfile.ROAList
}

func (c *Client) HandlePDU(cs *rtr.ClientSession, pdu rtr.PDU) {
	log.Debugf("Received: %v", pdu)
	switch pdu := pdu.(type) {
	case *rtr.PDUIPv4Prefix:
		rj := prefixfile.ROAJson{
			Prefix: pdu.Prefix.String(),
			ASN:    fmt.Sprintf("AS%v", pdu.ASN),
			Length: pdu.MaxLen,
		}
		c.Data.Data = append(c.Data.Data, rj)
		c.Data.Metadata.Counts++
	case *rtr.PDUIPv6Prefix:
		rj := prefixfile.ROAJson{
			Prefix: pdu.Prefix.String(),
			ASN:    fmt.Sprintf("AS%v", pdu.ASN),
			Length: pdu.MaxLen,
		}
		c.Data.Data = append(c.Data.Data, rj)
		c.Data.Metadata.Counts++
	case *rtr.PDUEndOfData:
		t := time.Now().UTC().UnixNano() / 1000000000
		c.Data.Metadata.Generated = int(t)
		c.Data.Metadata.Valid = int(pdu.SerialNumber)
		cs.Disconnect()
	case *rtr.PDUCacheResponse:
	default:
		cs.Disconnect()
	}
}

func (c *Client) ClientConnected(cs *rtr.ClientSession) {
	cs.SendResetQuery()
}

func (c *Client) ClientDisconnected(cs *rtr.ClientSession) {

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

	cc := rtr.ClientConfiguration{
		ProtocolVersion: rtr.PROTOCOL_VERSION_1,
		Log:             log.StandardLogger(),
	}

	client := &Client{
		Data: prefixfile.ROAList{
			Metadata: prefixfile.MetaData{},
			Data:     make([]prefixfile.ROAJson, 0),
		},
	}

	clientSession := rtr.NewClientSession(cc, client)

	configTLS := &tls.Config{
		InsecureSkipVerify: !*ValidateCert,
	}
	configSSH := &ssh.ClientConfig{
		Auth: make([]ssh.AuthMethod, 0),
		User: *SSHAuthUser,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			serverKeyHash := ssh.FingerprintSHA256(key)
			if *ValidateSSH {
				if serverKeyHash != fmt.Sprintf("SHA256:%v", *SSHServerKey) {
					return errors.New(fmt.Sprintf("Server key hash %v is different than expected key hash SHA256:%v", serverKeyHash, *SSHServerKey))
				}
			}
			log.Infof("Connected to server %v via ssh. Fingerprint: %v", remote.String(), serverKeyHash)
			return nil
		},
	}
	if authType, ok := authToId[*SSHAuth]; ok {
		if authType == METHOD_PASSWORD {
			password := *SSHAuthPassword
			if password == "" {
				password = os.Getenv(ENV_SSH_PASSWORD)
			}
			configSSH.Auth = append(configSSH.Auth, ssh.Password(password))
		} else if authType == METHOD_KEY {
			var keyBytes []byte
			var err error
			if *SSHAuthKey == "" {
				keyBytesStr := os.Getenv(ENV_SSH_KEY)
				keyBytes = []byte(keyBytesStr)
			} else {
				keyBytes, err = ioutil.ReadFile(*SSHAuthKey)
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
		log.Fatalf("Auth type %v unknown", *SSHAuth)
	}

	log.Infof("Connecting with %v to %v", *ConnType, *Connect)
	err := clientSession.Start(*Connect, typeToId[*ConnType], configTLS, configSSH)
	if err != nil {
		log.Fatal(err)
	}

	var f io.Writer
	if *OutFile != "" {
		ff, err := os.Create(*OutFile)
		defer ff.Close()
		if err != nil {
			log.Fatal(err)
		}
		f = ff
	} else {
		f = os.Stdout
	}

	enc := json.NewEncoder(f)
	err = enc.Encode(client.Data)
	if err != nil {
		log.Fatal(err)
	}
}
