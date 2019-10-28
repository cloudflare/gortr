package prefixfile

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDecodeJSON(t *testing.T) {
	data := `{
		  "slurmVersion": 1,
		  "validationOutputFilters": {
		   "prefixFilters": [
		     {
		      "prefix": "192.0.2.0/24",
		      "comment": "All VRPs encompassed by prefix"
		     },
		     {
		      "asn": 64496,
		      "comment": "All VRPs matching ASN"
		     },
		     {
		      "prefix": "198.51.100.0/24",
		      "asn": 64497,
		      "comment": "All VRPs encompassed by prefix, matching ASN"
		     }
		   ],
		   "bgpsecFilters": [
		     {
		      "asn": 64496,
		      "comment": "All keys for ASN"
		     },
		     {
		      "SKI": "Zm9v",
		      "comment": "Key matching Router SKI"
		     },
		     {
		      "asn": 64497,
		      "SKI": "YmFy",
		      "comment": "Key for ASN 64497 matching Router SKI"
		     }
		   ]
		  },
		  "locallyAddedAssertions": {
		   "prefixAssertions": [
		     {
		      "asn": 64496,
		      "prefix": "198.51.100.0/24",
		      "comment": "My other important route"
		     },
		     {
		      "asn": 64496,
		      "prefix": "2001:DB8::/32",
		      "maxPrefixLength": 48,
		      "comment": "My other important de-aggregated routes"
		     }
		   ],
		   "bgpsecAssertions": [
		     {
		      "asn": 64496,
		      "comment" : "My known key for my important ASN",
		      "SKI": "<some base64 SKI>",
		      "routerPublicKey": "<some base64 public key>"
		     }
		   ]
		  }
		}`
	buf := bytes.NewBufferString(data)
	decoded, err := DecodeJSONSlurm(buf)
	assert.Nil(t, err)
	asn, _ := decoded.ValidationOutputFilters.PrefixFilters[1].GetASN()
	_, asnEmpty := decoded.ValidationOutputFilters.PrefixFilters[0].GetASN()
	assert.Equal(t, uint32(64496), asn)
	assert.True(t, asnEmpty)
	assert.Equal(t, "192.0.2.0/24", decoded.ValidationOutputFilters.PrefixFilters[0].Prefix)
}

func TestFilterOnROAs(t *testing.T) {
	roas := []ROAJson{
		ROAJson{
			ASN:    "AS65001",
			Prefix: "192.168.0.0/25",
			Length: 25,
		},
		ROAJson{
			ASN:    "AS65002",
			Prefix: "192.168.1.0/24",
			Length: 24,
		},
		ROAJson{
			ASN:    "AS65003",
			Prefix: "192.168.2.0/24",
			Length: 24,
		},
		ROAJson{
			ASN:    "AS65004",
			Prefix: "10.0.0.0/24",
			Length: 24,
		},
	}

	slurm := SlurmValidationOutputFilters{
		PrefixFilters: []SlurmPrefixFilter{
			SlurmPrefixFilter{
				Prefix: "10.0.0.0/8",
			},
			SlurmPrefixFilter{
				ASN:    uint32(65001),
				Prefix: "192.168.0.0/24",
			},
			SlurmPrefixFilter{
				ASN: uint32(65002),
			},
		},
	}
	added, removed := slurm.FilterOnROAs(roas)
	assert.Len(t, added, 1)
	assert.Len(t, removed, 3)
	assert.Equal(t, uint32(65001), removed[0].GetASN())
}

func TestAssertROAs(t *testing.T) {
	slurm := SlurmLocallyAddedAssertions{
		PrefixAssertions: []SlurmPrefixAssertion{
			SlurmPrefixAssertion{
				ASN:     uint32(65001),
				Prefix:  "10.0.0.0/8",
				Comment: "Hello",
			},
			SlurmPrefixAssertion{
				ASN:    uint32(65001),
				Prefix: "192.168.0.0/24",
			},
			SlurmPrefixAssertion{
				ASN:             uint32(65003),
				Prefix:          "192.168.0.0/25",
				MaxPrefixLength: 26,
			},
		},
	}
	roas := slurm.AssertROAs()
	assert.Len(t, roas, 3)
}
