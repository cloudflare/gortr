package rtrlib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

type Logger interface{
	Debugf(string, ...interface{})
	Printf(string, ...interface{})
	Warnf(string, ...interface{})
	Errorf(string, ...interface{})
	Infof(string, ...interface{})
}

const (
	PROTOCOL_VERSION_0 = 0
	PROTOCOL_VERSION_1 = 1

	PDU_ID_SERIAL_NOTIFY  = 0
	PDU_ID_SERIAL_QUERY   = 1
	PDU_ID_RESET_QUERY    = 2
	PDU_ID_CACHE_RESPONSE = 3
	PDU_ID_IPV4_PREFIX    = 4
	PDU_ID_IPV6_PREFIX    = 6
	PDU_ID_END_OF_DATA    = 7
	PDU_ID_CACHE_RESET    = 8
	PDU_ID_ROUTER_KEY     = 9
	PDU_ID_ERROR_REPORT   = 10

	FLAG_ADDED   = 1
	FLAG_REMOVED = 0

	PDU_ERROR_CORRUPTDATA     = 0
	PDU_ERROR_INTERNALERR     = 1
	PDU_ERROR_NODATA          = 2
	PDU_ERROR_INVALIDREQUEST  = 3
	PDU_ERROR_BADPROTOVERSION = 4
	PDU_ERROR_BADPDUTYPE      = 5
	PDU_ERROR_WITHDRAWUNKNOWN = 6
	PDU_ERROR_DUPANNOUNCE     = 7
)

type PDU interface {
	Bytes() []byte
	Write(io.Writer)
	String() string
	SetVersion(uint8)
	GetVersion() uint8
	GetType() uint8
}

func TypeToString(t uint8) string {
	switch t {
	case PDU_ID_SERIAL_NOTIFY:
		return "Serial Notify"
	case PDU_ID_SERIAL_QUERY:
		return "Serial Query"
	case PDU_ID_RESET_QUERY:
		return "Reset Query"
	case PDU_ID_CACHE_RESPONSE:
		return "Cache Response"
	case PDU_ID_IPV4_PREFIX:
		return "IPv4 Prefix"
	case PDU_ID_IPV6_PREFIX:
		return "IPv6 Prefix"
	case PDU_ID_END_OF_DATA:
		return "End of Data"
	case PDU_ID_CACHE_RESET:
		return "Cache Reset"
	case PDU_ID_ROUTER_KEY:
		return "Router Key"
	case PDU_ID_ERROR_REPORT:
		return "Error Report"
	default:
		return fmt.Sprintf("Unknown type %v", t)
	}
}

func IsCorrectPDUVersion(pdu PDU, version uint8) bool {
	if version > 1 {
		return false
	}
	switch pdu.(type) {
	case *PDURouterKey:
		if version == 0 {
			return false
		}
	}
	return true
}

type PDUSerialNotify struct {
	Version      uint8
	SessionId    uint16
	SerialNumber uint32
}

func (pdu *PDUSerialNotify) String() string {
	return fmt.Sprintf("PDU Serial Notify v%v (session: %v): serial: %v", pdu.Version, pdu.SessionId, pdu.SerialNumber)
}

func (pdu *PDUSerialNotify) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUSerialNotify) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUSerialNotify) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUSerialNotify) GetType() uint8 {
	return PDU_ID_SERIAL_NOTIFY
}

func (pdu *PDUSerialNotify) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_SERIAL_NOTIFY))
	binary.Write(wr, binary.BigEndian, pdu.SessionId)
	binary.Write(wr, binary.BigEndian, uint32(12))
	binary.Write(wr, binary.BigEndian, uint32(pdu.SerialNumber))
}

type PDUSerialQuery struct {
	Version      uint8
	SessionId    uint16
	SerialNumber uint32
}

func (pdu *PDUSerialQuery) String() string {
	return fmt.Sprintf("PDU Serial Query v%v (session: %v): serial: %v", pdu.Version, pdu.SessionId, pdu.SerialNumber)
}

func (pdu *PDUSerialQuery) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUSerialQuery) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUSerialQuery) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUSerialQuery) GetType() uint8 {
	return PDU_ID_SERIAL_QUERY
}

func (pdu *PDUSerialQuery) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_SERIAL_QUERY))
	binary.Write(wr, binary.BigEndian, pdu.SessionId)
	binary.Write(wr, binary.BigEndian, uint32(12))
	binary.Write(wr, binary.BigEndian, uint32(pdu.SerialNumber))
}

type PDUResetQuery struct {
	Version uint8
}

func (pdu *PDUResetQuery) String() string {
	return fmt.Sprintf("PDU Reset Query v%v", pdu.Version)
}

func (pdu *PDUResetQuery) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUResetQuery) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUResetQuery) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUResetQuery) GetType() uint8 {
	return PDU_ID_RESET_QUERY
}

func (pdu *PDUResetQuery) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_RESET_QUERY))
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(8))
}

type PDUCacheResponse struct {
	Version   uint8
	SessionId uint16
}

func (pdu *PDUCacheResponse) String() string {
	return fmt.Sprintf("PDU Cache Response v%v (session: %v)", pdu.Version, pdu.SessionId)
}

func (pdu *PDUCacheResponse) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUCacheResponse) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUCacheResponse) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUCacheResponse) GetType() uint8 {
	return PDU_ID_CACHE_RESPONSE
}

func (pdu *PDUCacheResponse) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_CACHE_RESPONSE))
	binary.Write(wr, binary.BigEndian, pdu.SessionId)
	binary.Write(wr, binary.BigEndian, uint32(8))
}

type PDUIPv4Prefix struct {
	Version uint8
	Prefix  net.IPNet
	MaxLen  uint8
	ASN     uint32
	Flags   uint8
}

func (pdu *PDUIPv4Prefix) String() string {
	mask, _ := pdu.Prefix.Mask.Size()
	return fmt.Sprintf("PDU IPv4 Prefix v%v %v/%v(->/%v), origin: AS%v, flags: %v", pdu.Version, pdu.Prefix.IP, mask, pdu.MaxLen, pdu.ASN, pdu.Flags)
}

func (pdu *PDUIPv4Prefix) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUIPv4Prefix) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUIPv4Prefix) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUIPv4Prefix) GetType() uint8 {
	return PDU_ID_IPV4_PREFIX
}

func (pdu *PDUIPv4Prefix) Write(wr io.Writer) {
	mask, _ := pdu.Prefix.Mask.Size()
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_IPV4_PREFIX))
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(20))
	binary.Write(wr, binary.BigEndian, pdu.Flags)
	binary.Write(wr, binary.BigEndian, uint8(mask))
	binary.Write(wr, binary.BigEndian, pdu.MaxLen)
	binary.Write(wr, binary.BigEndian, uint8(0))
	binary.Write(wr, binary.BigEndian, pdu.Prefix.IP.To4())
	binary.Write(wr, binary.BigEndian, pdu.ASN)
}

type PDUIPv6Prefix struct {
	Version uint8
	Prefix  net.IPNet
	MaxLen  uint8
	ASN     uint32
	Flags   uint8
}

func (pdu *PDUIPv6Prefix) String() string {
	mask, _ := pdu.Prefix.Mask.Size()
	return fmt.Sprintf("PDU IPv6 Prefix v%v %v/%v(->/%v), origin: AS%v, flags: %v", pdu.Version, pdu.Prefix.IP, mask, pdu.MaxLen, pdu.ASN, pdu.Flags)
}

func (pdu *PDUIPv6Prefix) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUIPv6Prefix) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUIPv6Prefix) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUIPv6Prefix) GetType() uint8 {
	return PDU_ID_IPV6_PREFIX
}

func (pdu *PDUIPv6Prefix) Write(wr io.Writer) {
	mask, _ := pdu.Prefix.Mask.Size()
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_IPV6_PREFIX))
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(32))
	binary.Write(wr, binary.BigEndian, pdu.Flags)
	binary.Write(wr, binary.BigEndian, uint8(mask))
	binary.Write(wr, binary.BigEndian, pdu.MaxLen)
	binary.Write(wr, binary.BigEndian, uint8(0))
	binary.Write(wr, binary.BigEndian, pdu.Prefix.IP.To16())
	binary.Write(wr, binary.BigEndian, pdu.ASN)
}

type PDUEndOfData struct {
	Version      uint8
	SessionId    uint16
	SerialNumber uint32

	RefreshInterval uint32
	RetryInterval   uint32
	ExpireInterval  uint32
}

func (pdu *PDUEndOfData) String() string {
	return fmt.Sprintf("PDU End of Data v%v (session: %v): serial: %v", pdu.Version, pdu.SessionId, pdu.SerialNumber)
}

func (pdu *PDUEndOfData) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUEndOfData) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUEndOfData) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUEndOfData) GetType() uint8 {
	return PDU_ID_END_OF_DATA
}

func (pdu *PDUEndOfData) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_END_OF_DATA))
	binary.Write(wr, binary.BigEndian, pdu.SessionId)

	if pdu.Version == PROTOCOL_VERSION_0 {
		binary.Write(wr, binary.BigEndian, uint32(12))
		binary.Write(wr, binary.BigEndian, pdu.SerialNumber)
	} else if pdu.Version == PROTOCOL_VERSION_1 {
		binary.Write(wr, binary.BigEndian, uint32(24))
		binary.Write(wr, binary.BigEndian, pdu.SerialNumber)
		binary.Write(wr, binary.BigEndian, pdu.RefreshInterval)
		binary.Write(wr, binary.BigEndian, pdu.RetryInterval)
		binary.Write(wr, binary.BigEndian, pdu.ExpireInterval)
	}
}

type PDUCacheReset struct {
	Version uint8
}

func (pdu *PDUCacheReset) String() string {
	return fmt.Sprintf("PDU Cache Reset v%v", pdu.Version)
}

func (pdu *PDUCacheReset) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUCacheReset) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUCacheReset) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUCacheReset) GetType() uint8 {
	return PDU_ID_CACHE_RESET
}

func (pdu *PDUCacheReset) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_CACHE_RESET))
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(8))
}

type PDURouterKey struct {
	Version              uint8
	Flags                uint8
	SubjectKeyIdentifier [20]byte
	ASN                  uint32
	SubjectPublicKeyInfo uint32
}

func (pdu *PDURouterKey) String() string {
	return "PDU Router Key"
}

func (pdu *PDURouterKey) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDURouterKey) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDURouterKey) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDURouterKey) GetType() uint8 {
	return PDU_ID_ROUTER_KEY
}

func (pdu *PDURouterKey) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_ROUTER_KEY))
	binary.Write(wr, binary.BigEndian, uint8(pdu.Flags))
	binary.Write(wr, binary.BigEndian, uint8(0))
	binary.Write(wr, binary.BigEndian, uint32(36))
	binary.Write(wr, binary.BigEndian, pdu.SubjectKeyIdentifier)
	binary.Write(wr, binary.BigEndian, pdu.ASN)
	binary.Write(wr, binary.BigEndian, pdu.SubjectPublicKeyInfo)
}

type PDUErrorReport struct {
	Version   uint8
	ErrorCode uint16
	PDUCopy   []byte
	ErrorMsg  string
}

func (pdu *PDUErrorReport) String() string {
	return fmt.Sprintf("PDU Error report v%v (error code: %v): bytes PDU copy (%v): %v. Message: %v", pdu.Version, pdu.ErrorCode, len(pdu.PDUCopy), pdu.PDUCopy, pdu.ErrorMsg)
}

func (pdu *PDUErrorReport) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUErrorReport) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUErrorReport) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUErrorReport) GetType() uint8 {
	return PDU_ID_ERROR_REPORT
}

func (pdu *PDUErrorReport) Write(wr io.Writer) {
	nonnull := (pdu.ErrorMsg != "")
	addlen := 0
	if nonnull {
		addlen = 1
	}

	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_ERROR_REPORT))
	binary.Write(wr, binary.BigEndian, pdu.ErrorCode)
	binary.Write(wr, binary.BigEndian, uint32(12+len(pdu.PDUCopy)+4+len(pdu.ErrorMsg)+addlen))
	binary.Write(wr, binary.BigEndian, uint32(len(pdu.PDUCopy)))
	binary.Write(wr, binary.BigEndian, pdu.PDUCopy)
	binary.Write(wr, binary.BigEndian, uint32(len(pdu.ErrorMsg)+addlen))
	if nonnull {
		binary.Write(wr, binary.BigEndian, []byte(pdu.ErrorMsg))
		binary.Write(wr, binary.BigEndian, uint8(0))
		// Some clients require null-terminated strings
	}
}

func DecodeBytes(b []byte) (PDU, error) {
	buf := bytes.NewBuffer(b)
	return Decode(buf)
}

func Decode(rdr io.Reader) (PDU, error) {
	var pver uint8
	var pduType uint8
	var sessionId uint16
	var length uint32

	err := binary.Read(rdr, binary.BigEndian, &pver)
	if err != nil {
		return nil, err
	}
	err = binary.Read(rdr, binary.BigEndian, &pduType)
	if err != nil {
		return nil, err
	}
	err = binary.Read(rdr, binary.BigEndian, &sessionId)
	if err != nil {
		return nil, err
	}
	err = binary.Read(rdr, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}

	if length < 8 {
		return nil, errors.New(fmt.Sprintf("Wrong length: %v < 8", length))
	}
	toread := make([]byte, length-8)
	err = binary.Read(rdr, binary.BigEndian, toread)
	if err != nil {
		return nil, err
	}

	switch pduType {
	case PDU_ID_SERIAL_NOTIFY:
		if len(toread) != 4 {
			return nil, errors.New(fmt.Sprintf("Wrong length for Serial Notify PDU: %v != 4", len(toread)))
		}
		serial := binary.BigEndian.Uint32(toread)
		return &PDUSerialNotify{
			Version:      pver,
			SessionId:    sessionId,
			SerialNumber: serial,
		}, nil
	case PDU_ID_SERIAL_QUERY:
		if len(toread) != 4 {
			return nil, errors.New(fmt.Sprintf("Wrong length for Serial Query PDU: %v != 4", len(toread)))
		}
		serial := binary.BigEndian.Uint32(toread)
		return &PDUSerialQuery{
			Version:      pver,
			SessionId:    sessionId,
			SerialNumber: serial,
		}, nil
	case PDU_ID_RESET_QUERY:
		if len(toread) != 0 {
			return nil, errors.New(fmt.Sprintf("Wrong length for Reset Query PDU: %v != 0", len(toread)))
		}
		return &PDUResetQuery{
			Version: pver,
		}, nil
	case PDU_ID_CACHE_RESPONSE:
		if len(toread) != 0 {
			return nil, errors.New(fmt.Sprintf("Wrong length for Cache Response PDU: %v != 0", len(toread)))
		}
		return &PDUCacheResponse{
			Version:   pver,
			SessionId: sessionId,
		}, nil
	case PDU_ID_IPV4_PREFIX:
		if len(toread) != 12 {
			return nil, errors.New(fmt.Sprintf("Wrong length for IPv4 Prefix PDU: %v != 12", len(toread)))
		}
		prefixLen := int(toread[1])
		ip := toread[4:8]
		ipnet := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(prefixLen, 32),
		}
		asn := binary.BigEndian.Uint32(toread[8:])
		return &PDUIPv4Prefix{
			Version: pver,
			Flags:   uint8(toread[0]),
			MaxLen:  uint8(toread[2]),
			ASN:     asn,
			Prefix:  ipnet,
		}, nil
	case PDU_ID_IPV6_PREFIX:
		if len(toread) != 24 {
			return nil, errors.New(fmt.Sprintf("Wrong length for IPv6 Prefix PDU: %v != 24", len(toread)))
		}
		prefixLen := int(toread[1])
		ip := toread[4:20]
		ipnet := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(prefixLen, 128),
		}
		asn := binary.BigEndian.Uint32(toread[20:])
		return &PDUIPv6Prefix{
			Version: pver,
			Flags:   uint8(toread[0]),
			MaxLen:  uint8(toread[2]),
			ASN:     asn,
			Prefix:  ipnet,
		}, nil
	case PDU_ID_END_OF_DATA:
		if len(toread) != 4 && len(toread) != 16 {
			return nil, errors.New(fmt.Sprintf("Wrong length for End of Data PDU: %v != 4 or != 16", len(toread)))
		}

		var serial uint32
		var refreshInterval uint32
		var retryInterval uint32
		var expireInterval uint32
		if len(toread) == 4 {
			serial = binary.BigEndian.Uint32(toread)
		} else if len(toread) == 16 {
			serial = binary.BigEndian.Uint32(toread[0:4])
			refreshInterval = binary.BigEndian.Uint32(toread[4:8])
			retryInterval = binary.BigEndian.Uint32(toread[8:12])
			expireInterval = binary.BigEndian.Uint32(toread[12:16])
		}

		return &PDUEndOfData{
			Version:      pver,
			SessionId:    sessionId,
			SerialNumber: serial,
			RefreshInterval: refreshInterval,
			RetryInterval: retryInterval,
			ExpireInterval: expireInterval,
		}, nil
	case PDU_ID_CACHE_RESET:
		if len(toread) != 0 {
			return nil, errors.New(fmt.Sprintf("Wrong length for Cache Reset PDU: %v != 0", len(toread)))
		}
		return &PDUCacheReset{
			Version: pver,
		}, nil
	case PDU_ID_ROUTER_KEY:
		if len(toread) != 28 {
			return nil, errors.New(fmt.Sprintf("Wrong length for Router Key PDU: %v < 8", len(toread)))
		}
		asn := binary.BigEndian.Uint32(toread[20:24])
		spki := binary.BigEndian.Uint32(toread[24:28])
		ski := [20]byte{}
		copy(ski[:], toread[0:20])
		return &PDURouterKey{
			Version:              pver,
			SubjectKeyIdentifier: ski,
			ASN:                  asn,
			SubjectPublicKeyInfo: spki,
		}, nil
	case PDU_ID_ERROR_REPORT:
		if len(toread) < 8 {
			return nil, errors.New(fmt.Sprintf("Wrong length for Error Report PDU: %v < 8", len(toread)))
		}
		lenPdu := binary.BigEndian.Uint32(toread[0:4])
		errPdu := toread[4 : lenPdu+4]
		lenErrText := binary.BigEndian.Uint32(toread[lenPdu+4 : lenPdu+8])
		errMsg := string(toread[lenPdu+8 : lenPdu+8+lenErrText])
		return &PDUErrorReport{
			Version:   pver,
			ErrorCode: sessionId,
			PDUCopy:   errPdu,
			ErrorMsg:  errMsg,
		}, nil
	default:
		return nil, errors.New("Could not decode packet")
	}
	return nil, nil
}
