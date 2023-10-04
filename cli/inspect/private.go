package inspect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
)

func inspectPrivateKey(w io.Writer, bytes []byte) error {
	key, err := parsePrivateKey(bytes)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	fingerprint := sha256fingerprint(bytes)

	fmt.Fprintf(
		w,
		"Type:        PRIVATE KEY\nFingerprint: %s\n",
		fingerprint,
	)

	switch key := key.(type) {
	case *rsa.PrivateKey:
		fmt.Fprintf(w, "Algorithm:   RSA\nSize:        %d\n", key.Size()*8)

	case *ecdsa.PrivateKey:
		fmt.Fprintf(w, "Algorithm:   ECDSA\nCurve:       %s\n", key.Curve.Params().Name)

	case ed25519.PrivateKey:
		fmt.Fprintf(w, "Algorithm:   Ed25519\n")
	}

	return nil
}

// parsePrivateKey parses the given ASN.1 encoded private key and returns the
// relevant Go implementation. This function supports both PKCS#1 and PKCS#8
// private keys, as older versions of OpenSSL generated the former and later
// versions generated the latter both under the PEM type `PRIVATE KEY`.
// Additional support also exists for ECDSA private keys sources from PEM type
// `EC PRIVATE KEY`.
func parsePrivateKey(bytes []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unsupported private key format")
}
