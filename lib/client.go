package rtrlib

import (
	"net"
	"time"
	"crypto/tls"
)

type RTRClientSessionEventHandler interface {
	//RequestCache(*ClientSession)
	HandlePDU(*ClientSession, PDU)
}

type Logger interface{
	Debugf(string, ...interface{})
	Printf(string, ...interface{})
	Errorf(string, ...interface{})
	Infof(string, ...interface{})
}

type ClientSession struct {
	version uint8

	connected bool

	curserial uint32
	transmits chan PDU
	quit chan bool

	tcpconn       net.Conn

	handler RTRClientSessionEventHandler

	log Logger
}

type ClientConfiguration struct {
	ProtocolVersion uint8
	EnforceVersion  bool
	
	RefreshInterval uint32
	RetryInterval   uint32
	ExpireInterval  uint32

	Log Logger
}

func NewClientSession(configuration ClientConfiguration, handler RTRClientSessionEventHandler) *ClientSession {
	return &ClientSession{
		transmits: make(chan PDU, 256),
		quit: make(chan bool),
		log: configuration.Log,
		handler: handler,
	}
}

func (c *ClientSession) SendResetQuery() {
	pdu := &PDUResetQuery{}
	c.SendPDU(pdu)
}

func (c *ClientSession) SendSerialQuery(serial uint32) {
	pdu := &PDUSerialQuery{
		// to fill
	}
	c.SendPDU(pdu)
}

func (c *ClientSession) SendPDU(pdu PDU) {
	pdu.SetVersion(c.version)
	c.SendRawPDU(pdu)
}

func (c *ClientSession) SendRawPDU(pdu PDU) {
	c.transmits <- pdu
}

func (c *ClientSession) sendLoop() {
	for c.connected {
		select {
		case pdu := <-c.transmits:
			c.tcpconn.Write(pdu.Bytes())
		case <-c.quit:
			break
		}
	}
}

func (c *ClientSession) refreshLoop() {
	for c.connected {
		select {
		case <-time.After(20*time.Second):
			// send refresh
		}
	}
}

func (c *ClientSession) Disconnect() {
	c.connected = false
	//log.Debugf("Disconnecting client %v", c.String())
	//if c.handler != nil {
	//	c.handler.ClientDisconnected(c)
	//}
	select {
	case c.quit <- true:
	default:

	}

	c.tcpconn.Close()
}

func (c *ClientSession) StartWithConn(tcpconn net.Conn) error {
	c.tcpconn = tcpconn
	c.connected = true
	//if c.handler != nil {
	//	c.handler.ClientConnected(c)
	//}

	go c.sendLoop()
	c.SendResetQuery()
	for c.connected {
		dec, err := Decode(c.tcpconn)
		if err != nil || dec == nil {
			if c.log != nil {
				c.log.Errorf("Error %v", err)	
			}
			c.Disconnect()
			return err
		}
		if c.handler != nil {
			c.handler.HandlePDU(c, dec)
		}
	}

	return nil
}

func (c *ClientSession) Start(addr string, useTls bool, config *tls.Config) error {
	addrTCP, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	if useTls {
		tcpconn, err := tls.Dial("tcp", addr, config)
		if err != nil {
			return err
		}
		return c.StartWithConn(tcpconn)
	} else {
		tcpconn, err := net.DialTCP("tcp", nil, addrTCP)
		if err != nil {
			return err
		}
		return c.StartWithConn(tcpconn)
	}
	return nil
}