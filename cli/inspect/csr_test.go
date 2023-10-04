package inspect

import (
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInspectCSR(t *testing.T) {
	tests := []struct {
		name   string
		csr    string
		output string
		err    error
	}{
		{
			"Simple", `-----BEGIN CERTIFICATE REQUEST-----
MIIBAjCBqQIBADBHMQswCQYDVQQGEwJHQjEVMBMGA1UEChMMQUNNRSBMaW1pdGVk
MQswCQYDVQQLEwJJVDEUMBIGA1UEAxMLZXhhbXBsZS5vcmcwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQWN20L/psDuL9PwpXybJyx7ZrtHOxr8KMLRoTlFDY/l5Hs
W6NPyRF8p8SqZ0mE9sp2TaobbqY/YsBCKKl0zDWvoAAwCgYIKoZIzj0EAwIDSAAw
RQIhAIIkcGof/lJEiaFg3G2UMKmTo6Pi+XAMnQbf/wwa+QmiAiBlo/FiBiWaAmGT
B6RepP6zL3i9UxysOQ4VTsIl5u0mVg==
-----END CERTIFICATE REQUEST-----`, `Type:        CERTIFICATE REQUEST
Version:     0
Signature:   ECDSA-SHA256
Fingerprint: SHA256:ePB8M8Ye9uDOL5KdeLLP9FGzxJ9EoWAv9gqaT64X1PE=
Public Key:  SHA256:bXH+hqm75yQqkqAVR6K1FgqWacfxdR12ciWti2ndSVw=
Subject:     CN=example.org,OU=IT,O=ACME Limited,C=GB
`, nil,
		},
		{
			"DNSName", `-----BEGIN CERTIFICATE REQUEST-----
MIIBKjCB0gIBADBHMQswCQYDVQQGEwJHQjEVMBMGA1UEChMMQUNNRSBMaW1pdGVk
MQswCQYDVQQLEwJJVDEUMBIGA1UEAxMLZXhhbXBsZS5vcmcwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQWN20L/psDuL9PwpXybJyx7ZrtHOxr8KMLRoTlFDY/l5Hs
W6NPyRF8p8SqZ0mE9sp2TaobbqY/YsBCKKl0zDWvoCkwJwYJKoZIhvcNAQkOMRow
GDAWBgNVHREEDzANggtleGFtcGxlLm9yZzAKBggqhkjOPQQDAgNHADBEAiAYsWMi
/wIvlIt+dC4qG46z6UALdQl+S8dcvwzP71YKgAIgeRe9Br1yjUNUNw+Uaho6yCDz
9fMzbH7tb6ozKeCcsrY=
-----END CERTIFICATE REQUEST-----`, `Type:        CERTIFICATE REQUEST
Version:     0
Signature:   ECDSA-SHA256
Fingerprint: SHA256:56inJxON3oDFRNzraDlRgdMycRTPaF+A1g5ko12gD7o=
Public Key:  SHA256:bXH+hqm75yQqkqAVR6K1FgqWacfxdR12ciWti2ndSVw=
Subject:     CN=example.org,OU=IT,O=ACME Limited,C=GB
DNS Names:
  example.org
`, nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var w strings.Builder

			block, _ := pem.Decode([]byte(test.csr))

			err := inspectCSR(&w, block.Bytes)
			if test.err == nil {
				if assert.NoError(t, err) {
					assert.Equal(t, test.output, w.String())
				}
			} else {
				assert.Equal(t, test.err, err)
			}
		})
	}
}
