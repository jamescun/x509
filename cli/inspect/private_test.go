package inspect

import (
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInspectPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		private string
		output  string
		err     error
	}{
		{
			"RSA/1024/PKCS#8", `-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMC/rrzI5m6ws9cn
VsH8BYBhhaK2Dzg1Lm+EbctczYwo+ApCalsPQapUoNDBvFxOQBpXTv1u9fVzsdZD
xkNSBRjOfS8NH3un5dn4vF4FlhGNAT6iG6ZpDP/1WD2DH4WNQjGebFQ2PzCIHls7
MVculddyoTjJ3Qlggzi2rs8c/Y2/AgMBAAECgYAKclkmIj1bAni80IUDPoWNz7tO
dk+c3EUIBkVtIDqDvjSzWaYqCUml0bBloBp1ZkhTJShC1CDAjOS2mDXGsEtWVMOC
/asojNk/Chq60B1p4xtUqOAauHJ0HjJDSHcdjURUURFh9YT5+heT/KHXIkqB9k8s
K52Hsecm6sYPPc+qAQJBANdaVGz09Ac32le5SbkLFS/5FbYzw+c1aa7a9S+EdhXu
vRA4dH/gPe1wksrQiDaKkZ4MM/T9tkLUVlUz8H+dEccCQQDlISRXpp9ETEbiCaTQ
kAfbgK5iVlQNk8xtPJltYPgWU1dWcMXYdzM/d7klANNIpX0fdI1HfRFtVXSxQ/MX
sKRJAkB7/98s/b6liVuHt4Djs6X3gY0m5JegwfigXiNfwP3dkyH5/QfXud7uoStk
7L4B6bf/MTeZkZ0ozesIFGgekupxAkBvF12GfcvUkmL/rwtQ77RPkZl7Jj4Egzdn
cy00YgKG2IuM5oqWRFz9la+XqEnIfCwpNxpUoef0Ka21UKupPcS5AkAvpzsUCY1d
dzum7FcoAJDd8K4Xxuv6IKlqtWROq2v+P8XWJLDvoCBkRjUhA9D3iy6bK/t6pz28
/0MjL0KzMaVz
-----END PRIVATE KEY-----`, `Type:        PRIVATE KEY
Fingerprint: SHA256:40ksyhYwt5QUrVrfnD0hZkuSqnuRDBasVo/2VkytZC4=
Algorithm:   RSA
Size:        1024
`, nil,
		},
		{
			"ECDSA/P256/PKCS#8", `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyxYlQ6WClP2kuXbg
nUrtJZFJGA2DdWoigfDhg6A8yr6hRANCAAQCV2AW+PV2yRSbN9pG+ZUsQiKdlCK5
vtDqam+IRMwTwov/fIocKI2eJGP6CASH9Fd43/5rwJYJiQjusz51V9EL
-----END PRIVATE KEY-----`, `Type:        PRIVATE KEY
Fingerprint: SHA256:adPDcEngK4Ogov80Cs8HXj9Rq/TXCvOOLtM/qu5C1qs=
Algorithm:   ECDSA
Curve:       P-256
`, nil,
		},
		{
			"Ed25519/PKCS#8", `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFs8lzziIRzbW2EeZeOM2FFHOWhiEPHWAaJz/OSMgNe3
-----END PRIVATE KEY-----`, `Type:        PRIVATE KEY
Fingerprint: SHA256:9kr27LozbETYBEkjoc+R/KK2FStugAouM2qs8bXWBu8=
Algorithm:   Ed25519
`, nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var w strings.Builder

			block, _ := pem.Decode([]byte(test.private))

			err := inspectPrivateKey(&w, block.Bytes)
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
