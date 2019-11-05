package prefixfile

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
)

type SlurmPrefixFilter struct {
	Prefix  string
	ASN     interface{}
	Comment string
}

func (pf *SlurmPrefixFilter) GetASN() (uint32, bool) {
	if pf.ASN == nil {
		return 0, true
	} else {
		switch asn := pf.ASN.(type) {
		case json.Number:
			c, _ := asn.Int64()
			return uint32(c), false
		case uint32:
			return asn, false
		default:
			return 0, true
		}
	}
}

func (pf *SlurmPrefixFilter) GetPrefix() *net.IPNet {
	_, prefix, _ := net.ParseCIDR(pf.Prefix)
	return prefix
}

type SlurmValidationOutputFilters struct {
	PrefixFilters []SlurmPrefixFilter
}

type SlurmPrefixAssertion struct {
	Prefix          string
	ASN             uint32
	MaxPrefixLength int
	Comment         string
}

func (pa *SlurmPrefixAssertion) GetASN() uint32 {
	return pa.ASN
}

func (pa *SlurmPrefixAssertion) GetPrefix() *net.IPNet {
	_, prefix, _ := net.ParseCIDR(pa.Prefix)
	return prefix
}

func (pa *SlurmPrefixAssertion) GetMaxLen() int {
	return pa.MaxPrefixLength
}

type SlurmLocallyAddedAssertions struct {
	PrefixAssertions []SlurmPrefixAssertion
}

type SlurmConfig struct {
	SlurmVersion            int
	ValidationOutputFilters SlurmValidationOutputFilters
	LocallyAddedAssertions  SlurmLocallyAddedAssertions
}

func DecodeJSONSlurm(buf io.Reader) (*SlurmConfig, error) {
	slurm := &SlurmConfig{}
	dec := json.NewDecoder(buf)
	dec.UseNumber()
	err := dec.Decode(slurm)
	if err != nil {
		return nil, err
	}
	return slurm, nil
}

func (s *SlurmValidationOutputFilters) FilterOnROAs(roas []ROAJson) ([]ROAJson, []ROAJson) {
	added := make([]ROAJson, 0)
	removed := make([]ROAJson, 0)
	if s.PrefixFilters == nil || len(s.PrefixFilters) == 0 {
		return added, removed
	}
	for _, roa := range roas {
		rPrefix := roa.GetPrefix()
		var rIPStart net.IP
		var rIPEnd net.IP
		if rPrefix != nil {
			rIPStart = rPrefix.IP.To16()
			rIPEnd = GetIPBroadcast(*rPrefix).To16()
		}

		var wasRemoved bool
		for _, filter := range s.PrefixFilters {
			fPrefix := filter.GetPrefix()
			fASN, fASNEmpty := filter.GetASN()
			match := true
			if match && fPrefix != nil && rPrefix != nil {

				if !(fPrefix.Contains(rIPStart) && fPrefix.Contains(rIPEnd)) {
					match = false
				}
			}
			if match && !fASNEmpty {
				if roa.GetASN() != fASN {
					match = false
				}
			}
			if match {
				removed = append(removed, roa)
				wasRemoved = true
				break
			}
		}

		if !wasRemoved {
			added = append(added, roa)
		}
	}
	return added, removed
}

func (s *SlurmConfig) FilterOnROAs(roas []ROAJson) ([]ROAJson, []ROAJson) {
	return s.ValidationOutputFilters.FilterOnROAs(roas)
}

func (s *SlurmLocallyAddedAssertions) AssertROAs() []ROAJson {
	roas := make([]ROAJson, 0)
	if s.PrefixAssertions == nil || len(s.PrefixAssertions) == 0 {
		return roas
	}
	for _, assertion := range s.PrefixAssertions {
		prefix := assertion.GetPrefix()
		size, _ := prefix.Mask.Size()
		maxLength := assertion.MaxPrefixLength
		if assertion.MaxPrefixLength <= size {
			maxLength = size
		}
		roas = append(roas, ROAJson{
			ASN:    fmt.Sprintf("AS%v", assertion.ASN),
			Prefix: assertion.Prefix,
			Length: uint8(maxLength),
			TA:     assertion.Comment,
		})
	}
	return roas
}

func (s *SlurmConfig) AssertROAs() []ROAJson {
	return s.LocallyAddedAssertions.AssertROAs()
}

func (s *SlurmConfig) FilterAssert(roas []ROAJson) []ROAJson {
	a, _ := s.FilterOnROAs(roas)
	b := s.AssertROAs()
	return append(a, b...)
}
