package inspect

import (
	"crypto/x509"
	"fmt"
	"io"
)

func inspectCSR(w io.Writer, bytes []byte) error {
	csr, err := x509.ParseCertificateRequest(bytes)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	fingerprint := sha256fingerprint(bytes)

	publicKey, err := publicKeyFingerprint(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}

	fmt.Fprintf(
		w,
		"Type:        CERTIFICATE REQUEST\nVersion:     %d\nSignature:   %s\nFingerprint: %s\nPublic Key:  %s\nSubject:     %s\n",
		csr.Version, csr.SignatureAlgorithm.String(), fingerprint, publicKey, csr.Subject.String(),
	)

	if len(csr.DNSNames) > 0 {
		fmt.Fprintln(w, "DNS Names:")

		for _, name := range csr.DNSNames {
			fmt.Fprintf(w, "  %s\n", name)
		}
	}

	if len(csr.IPAddresses) > 0 {
		fmt.Fprintln(w, "IP Addresses:")

		for _, ip := range csr.IPAddresses {
			fmt.Fprintf(w, "  %s\n", ip)
		}
	}

	return nil
}
