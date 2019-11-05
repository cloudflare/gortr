package prefixfile

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
)

func (roalist *ROAList) GenerateDigest() ([]byte, []byte, error) {
	signroa := make([]string, 0)
	for _, v := range roalist.Data {
		signroa = append(signroa, fmt.Sprintf("%v,%v,%v,", v.Prefix, v.Length, v.ASN))
	}
	sort.Strings(signroa)
	sorted := strings.Join(signroa, "")
	dgst1 := sha256.Sum256([]byte(sorted))
	dgst2 := sha256.Sum256([]byte(fmt.Sprintf("%v,%v%v", roalist.Metadata.Generated, sorted, roalist.Metadata.Valid)))

	return dgst1[:], dgst2[:], nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (roalist *ROAList) CheckFile(key *ecdsa.PublicKey) (bool, bool, error) {
	dgst1, dgst2, err := roalist.GenerateDigest()
	if err != nil {
		return false, false, err
	}
	signatureB, err := hex.DecodeString(roalist.Metadata.SignatureDate)
	if err != nil {
		return false, false, err
	}
	var sign1 ecdsaSignature
	_, err = asn1.Unmarshal(signatureB, &sign1)
	if err != nil {
		return false, false, err
	}
	signatureB, err = hex.DecodeString(roalist.Metadata.Signature)
	if err != nil {
		return false, false, err
	}
	var sign2 ecdsaSignature
	_, err = asn1.Unmarshal(signatureB, &sign2)
	if err != nil {
		return false, false, err
	}
	verify1 := ecdsa.Verify(key, dgst1, sign1.R, sign1.S)
	verify2 := ecdsa.Verify(key, dgst2, sign2.R, sign2.S)
	return verify1, verify2, err
}

func (roalist *ROAList) Sign(privkey *ecdsa.PrivateKey) (string, string, error) {
	dgst1, dgst2, err := roalist.GenerateDigest()
	if err != nil {
		return "", "", err
	}
	sign1, err := privkey.Sign(rand.Reader, dgst1, nil)
	if err != nil {
		return "", "", err
	}
	sign2, err := privkey.Sign(rand.Reader, dgst2, nil)
	if err != nil {
		return "", "", err
	}

	return hex.EncodeToString(sign1), hex.EncodeToString(sign2), nil
}

type ROAJson struct {
	Prefix string      `json:"prefix"`
	Length uint8       `json:"maxLength"`
	ASN    interface{} `json:"asn"`
	TA     string      `json:"ta,omitempty"`
}

type MetaData struct {
	Counts        int    `json:"counts"`
	Generated     int    `json:"generated"`
	Valid         int    `json:"valid,omitempty"`
	Signature     string `json:"signature,omitempty"`
	SignatureDate string `json:"signatureDate,omitempty"`
}

type ROAList struct {
	Metadata MetaData  `json:"metadata,omitempty"`
	Data     []ROAJson `json:"roas"`
}

func (roa *ROAJson) GetASN2() (uint32, error) {
	switch asnc := roa.ASN.(type) {
	case string:
		asnStr := strings.TrimLeft(asnc, "aAsS")
		asnInt, err := strconv.ParseUint(asnStr, 10, 32)
		if err != nil {
			return 0, errors.New(fmt.Sprintf("Could not decode ASN: %v as part of ROA", roa.ASN))
		}
		asn := uint32(asnInt)
		return asn, nil
	case float64:
		return uint32(asnc), nil
	case int:
		return uint32(asnc), nil
	default:
		return 0, errors.New(fmt.Sprintf("Could not decode ASN: %v as part of ROA", roa.ASN))
	}
}

func (roa *ROAJson) GetASN() uint32 {
	asn, _ := roa.GetASN2()
	return asn
}

func (roa *ROAJson) SetASN(asn uint32) {
	roa.ASN = fmt.Sprintf("AS%v", asn)
}

func (roa *ROAJson) GetPrefix2() (*net.IPNet, error) {
	_, prefix, err := net.ParseCIDR(roa.Prefix)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Could not decode prefix: %v as part of ROA", roa.Prefix))
	}
	return prefix, nil
}

func (roa *ROAJson) GetPrefix() *net.IPNet {
	prefix, _ := roa.GetPrefix2()
	return prefix
}

func (roa *ROAJson) GetMaxLen() int {
	return int(roa.Length)
}

func (roa *ROAJson) String() string {
	return fmt.Sprintf("%v/%v/%v", roa.Prefix, roa.Length, roa.ASN)
}
