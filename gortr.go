package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	rtr "github.com/cloudflare/gortr/lib"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"
	"strings"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const AppVersion = "GoRTR v2018.9.0"

var (
	MetricsAddr = flag.String("metrics.addr", "127.0.0.1:8080", "Metrics address")
	MetricsPath = flag.String("metrics.path", "/metrics", "Metrics path")

	Bind = flag.String("bind", "127.0.0.1:8282", "Bind address")

	BindTLS = flag.String("tls.bind", "", "Bind address for TLS")
	TLSCert = flag.String("tls.cert", "", "Certificate path")
	TLSKey  = flag.String("tls.key", "", "Private key path")

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

func fetch_file(file string) ([]byte, error) {
	var f io.Reader
	var err error
	if len(file) > 8 && (file[0:7] == "http://" || file[0:8] == "https://") {
		fhttp, err := http.Get(file)
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

func check_file(data []byte) ([]byte, error) {
	hsum := sha256.Sum256(data)
	return hsum[:], nil
}

func decode_data(data []byte) ([]rtr.ROA, int, int, int) {
	buf := bytes.NewBuffer(data)
	dec := json.NewDecoder(buf)

	var roalistjson ROAList
	dec.Decode(&roalistjson)
	//log.Debugf("%v", roalistjson)
	filterDuplicates := make(map[string]bool)

	roalist := make([]rtr.ROA, 0)

	var count int
	var countv4 int
	var countv6 int
	for _, v := range roalistjson.Data {
		_, prefix, _ := net.ParseCIDR(v.Prefix)
		asnStr := v.ASN[2:len(v.ASN)]
		asnInt, _ := strconv.Atoi(asnStr)
		asn := uint32(asnInt)

		count++
		if prefix.IP.To4() != nil {
			countv4++
		} else if prefix.IP.To16() != nil {
			countv6++
		}

		key := fmt.Sprintf("%v%v%v", prefix, asn, v.Length)
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

func (s *state) update_file(file string) {
	log.Debugf("Refreshing cache")
	data, err := fetch_file(file)
	if err != nil {
		log.Error(err)
		return
	}
	hsum, _ := check_file(data)
	if s.lasthash != nil {
		cres := bytes.Compare(s.lasthash, hsum)
		if cres == 0 {
			log.Info("Identical files")
			return
		}
	}
	s.lastts = time.Now().UTC()
	s.lastdata = data
	roas, count, countv4, countv6 := decode_data(s.lastdata)
	log.Infof("New update (%v uniques, %v total prefixes). %v bytes. Updating sha256 hash %x -> %x",
		len(roas), count, len(s.lastconverted), s.lasthash, hsum)
	s.lasthash = hsum

	s.server.AddROAs(roas)

	sessid, _ := s.server.GetSessionId(nil)
	serial, _ := s.server.GetCurrentSerial(sessid)
	log.Infof("Updated added, new serial %v", serial)
	if s.sendNotifs {
		log.Debugf("Sending motifications to clients")
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
}

func (s *state) routine_update(file string, interval int) {
	log.Debugf("Starting refresh routine (file: %v, interval: %vs)", file, interval)
	for {
		select {
		case <-time.After(time.Duration(interval) * time.Second):
			s.update_file(file)
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

	LastRefresh.WithLabelValues(file).Set(float64(refreshed.UnixNano()/1e9))

}


type ROAJson struct {
	Prefix string `json:"prefix"`
	Length uint8  `json:"maxLength"`
	ASN    string `json:"asn"`
	TA     string `json:"ta"`
}

type ROAList struct {
	Data []ROAJson `json:"roas"`
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
		Loglevel: uint32(lvl),
	}

	var me *metricsEvent
	if *MetricsAddr != "" {
		initMetrics()
		go metricHTTP()
		me = &metricsEvent{}
	}

	server := rtr.NewServer(sc, me, deh)
	deh.SetROAManager(server)

	s := state{
		server: server,
		metricsEvent: me,
		sendNotifs: *SendNotifs,
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

	s.update_file(*CacheBin)
	s.routine_update(*CacheBin, *RefreshInterval)

}
