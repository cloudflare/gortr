package main

import (
	"flag"
	"fmt"
	rtr "github.com/cloudflare/gortr/lib"
	"github.com/cloudflare/gortr/prefixfile"
	log "github.com/sirupsen/logrus"
	"os"
	"runtime"
	"encoding/json"
	"time"
	"io"
	"crypto/tls"
)

const AppVersion = "RTRdump 0.9.4"

var (
	Connect = flag.String("connect", "127.0.0.1:8282", "Connection address")
	OutFile = flag.String("file", "output.json", "Output file")

	UseTLS = flag.Bool("tls.enable", false, "Use TLS")
	ValidateCert = flag.Bool("tls.validate", true, "Validate TLS")

	RefreshInterval = flag.Int("refresh", 600, "Refresh interval in seconds")

	LogLevel = flag.String("loglevel", "info", "Log level")
	Version  = flag.Bool("version", false, "Print version")
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
				ASN: fmt.Sprintf("AS%v", pdu.ASN),
				Length: pdu.MaxLen,
			}
			c.Data.Data = append(c.Data.Data, rj)
			c.Data.Metadata.Counts++
		case *rtr.PDUIPv6Prefix:
			rj := prefixfile.ROAJson{
				Prefix: pdu.Prefix.String(),
				ASN: fmt.Sprintf("AS%v", pdu.ASN),
				Length: pdu.MaxLen,
			}
			c.Data.Data = append(c.Data.Data, rj)
			c.Data.Metadata.Counts++
		case *rtr.PDUEndOfData:
			t := time.Now().UTC().UnixNano()/1000000000
			c.Data.Metadata.Generated = int(t)
			c.Data.Metadata.Valid = int(pdu.SerialNumber)
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
		Log: log.StandardLogger(),
	}

	client := &Client{
		Data: prefixfile.ROAList{
			Metadata: prefixfile.MetaData{
			},
			Data: make([]prefixfile.ROAJson, 0),
		},
	}

	clientSession := rtr.NewClientSession(cc, client)

	config := &tls.Config{
		InsecureSkipVerify: !*ValidateCert,
	}
	err := clientSession.Start(*Connect, *UseTLS, config)
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
