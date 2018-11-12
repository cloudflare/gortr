package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/cloudflare/gortr/prefixfile"
	rtr "github.com/cloudflare/gortr/lib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const AppVersion = "GoRTR 0.9.4"

var (
	MetricsAddr = flag.String("metrics.addr", ":8080", "Metrics address")
	MetricsPath = flag.String("metrics.path", "/metrics", "Metrics path")

	Bind = flag.String("bind", ":8282", "Bind address")

	BindTLS = flag.String("tls.bind", "", "Bind address for TLS")
	TLSCert = flag.String("tls.cert", "", "Certificate path")
	TLSKey  = flag.String("tls.key", "", "Private key path")

	TimeCheck = flag.Bool("checktime", true, "Check if file is still valid")
	Verify    = flag.Bool("verify", true, "Check signature using provided public key")
	PublicKey = flag.String("verify.key", "cf.pub", "Public key path (PEM file)")

	CacheBin        = flag.String("cache", "https://rpki.cloudflare.com/rpki.json", "URL of the cached JSON data")
	RefreshInterval = flag.Int("refresh", 600, "Refresh interval in seconds")
	MaxConn         = flag.Int("maxconn", 0, "Max simultaneous connections (0 to disable limit)")
	SendNotifs      = flag.Bool("notifications", true, "Send notifications to clients")

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
			Help: "Last refresh.",
		},
		[]string{"path"},
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
)

func initMetrics() {
	prometheus.MustRegister(NumberOfROAs)
	prometheus.MustRegister(LastRefresh)
	prometheus.MustRegister(ClientsMetric)
	prometheus.MustRegister(PDUsRecv)
}

func metricHTTP() {
	http.Handle(*MetricsPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(*MetricsAddr, nil))
}

func fetchFile(file string) ([]byte, error) {
	var f io.Reader
	var err error
	if len(file) > 8 && (file[0:7] == "http://" || file[0:8] == "https://") {

		client := &http.Client{}
		req, err := http.NewRequest("GET", file, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "text/json")

		fhttp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		f = fhttp.Body
	} else {
		f, err = os.Open(file)
		if err != nil {
			return nil, err
		}
	}
	data, err2 := ioutil.ReadAll(f)
	if err2 != nil {
		return nil, err2
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

func processData(roalistjson *prefixfile.ROAList) ([]rtr.ROA, int, int, int) {
	filterDuplicates := make(map[string]bool)

	roalist := make([]rtr.ROA, 0)

	var count int
	var countv4 int
	var countv6 int
	for _, v := range roalistjson.Data {
		_, prefix, _ := net.ParseCIDR(v.Prefix)
		asnStr := v.ASN[2:len(v.ASN)]
		asnInt, _ := strconv.ParseUint(asnStr, 10, 32)
		asn := uint32(asnInt)

		count++
		if prefix.IP.To4() != nil {
			countv4++
		} else if prefix.IP.To16() != nil {
			countv6++
		}

		key := fmt.Sprintf("%v,%v,%v", prefix, asn, v.Length)
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

func (s *state) updateFile(file string) error {
	log.Debugf("Refreshing cache from %v", file)
	data, err := fetchFile(file)
	if err != nil {
		log.Error(err)
		return err
	}
	hsum, _ := checkFile(data)
	if s.lasthash != nil {
		cres := bytes.Compare(s.lasthash, hsum)
		if cres == 0 {
			return errors.New("Identical files")
		}
	}

	s.lastts = time.Now().UTC()
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

	roas, count, countv4, countv6 := processData(roalistjson)
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
		s.metricsEvent.UpdateMetrics(countv4, countv6, countv4_dup, countv6_dup, s.lastts, file)
	}
	return nil
}

func (s *state) routineUpdate(file string, interval int) {
	log.Debugf("Starting refresh routine (file: %v, interval: %vs)", file, interval)
	for {
		select {
		case <-time.After(time.Duration(interval) * time.Second):
			err := s.updateFile(file)
			if err != nil {
				log.Errorf("Error updating: %v", err)
			}
		}
	}
}

type state struct {
	lastdata      []byte
	lastconverted []byte
	lasthash      []byte
	lastts        time.Time
	sendNotifs    bool

	server *rtr.Server

	metricsEvent *metricsEvent

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

func (m *metricsEvent) UpdateMetrics(numIPv4 int, numIPv6 int, numIPv4filtered int, numIPv6filtered int, refreshed time.Time, file string) {
	NumberOfROAs.WithLabelValues("ipv4", "filtered", file).Set(float64(numIPv4filtered))
	NumberOfROAs.WithLabelValues("ipv4", "unfiltered", file).Set(float64(numIPv4))
	NumberOfROAs.WithLabelValues("ipv6", "filtered", file).Set(float64(numIPv6filtered))
	NumberOfROAs.WithLabelValues("ipv6", "unfiltered", file).Set(float64(numIPv6))
	LastRefresh.WithLabelValues(file).Set(float64(refreshed.UnixNano() / 1e9))
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

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	deh := &rtr.DefaultRTREventHandler{}

	sc := rtr.ServerConfiguration{
		ProtocolVersion: rtr.PROTOCOL_VERSION_0,
		KeepDifference:  3,
		Loglevel:        uint32(lvl),
	}

	var me *metricsEvent
	if *MetricsAddr != "" {
		initMetrics()
		go metricHTTP()
		me = &metricsEvent{}
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
	}

	if *Bind == "" && *BindTLS == "" {
		log.Fatalf("Specify at least a bind address")
	}

	if *Bind != "" {
		go server.Start(*Bind)
	}
	if *BindTLS != "" {
		cert, err := tls.LoadX509KeyPair(*TLSCert, *TLSKey)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		go server.StartTLS(*BindTLS, tlsConfig)
	}

	err := s.updateFile(*CacheBin)
	if err != nil {
		log.Errorf("Error updating: %v", err)
	}
	s.routineUpdate(*CacheBin, *RefreshInterval)

}
