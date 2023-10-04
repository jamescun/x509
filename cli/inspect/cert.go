package inspect

import (
	"crypto/x509"
	"fmt"
	"io"
)

func inspectCert(w io.Writer, bytes []byte) error {
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	fingerprint := sha256fingerprint(bytes)

	publicKey, err := publicKeyFingerprint(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}

	fmt.Fprintf(
		w,
		"Type:        CERTIFICATE\nVersion:     %d\nSignature:   %s\nFingerprint: %s\nPublic Key:  %s\nIssuer:      %s\nSubject:     %s\n",
		cert.Version, cert.SignatureAlgorithm.String(), fingerprint, publicKey, cert.Issuer.String(), cert.Subject.String(),
	)

	if len(cert.DNSNames) > 0 {
		fmt.Fprintln(w, "DNS Names:")

		for _, name := range cert.DNSNames {
			fmt.Fprintf(w, "  %s\n", name)
		}
	}

	if len(cert.IPAddresses) > 0 {
		fmt.Fprintln(w, "IP Addresses:")

		for _, ip := range cert.IPAddresses {
			fmt.Fprintf(w, "  %s\n", ip)
		}
	}

	return nil
}
