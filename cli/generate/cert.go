package generate

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	validity   time.Duration
	serverAuth bool
	clientAuth bool
)

var genCert = &cobra.Command{
	Use:   "cert",
	Short: "generate a self-signed certificate",

	Aliases: []string{
		"certificate",
	},

	PreRunE: func(cmd *cobra.Command, args []string) error {
		err := genCSR.PreRunE(cmd, args)
		if err != nil {
			return err
		}

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		privateKey, err := readPrivateKey(keyPath)
		if err != nil {
			return fmt.Errorf("could not read private key: %w", err)
		}

		publicKey, ok := privateKey.(interface {
			Public() crypto.PublicKey
		})
		if !ok {
			return fmt.Errorf("private key has no public key equivalent")
		}

		name := pkix.Name{
			Country:            country,
			Organization:       org,
			OrganizationalUnit: orgUnit,
			Province:           state,
			Locality:           locality,
			CommonName:         commonName,
		}

		serialNumber, err := randomSerialNumber()
		if err != nil {
			return fmt.Errorf("could not generate random serial number: %w", err)
		}

		now := time.Now()

		cert := &x509.Certificate{
			Version:               3,
			SerialNumber:          serialNumber,
			Issuer:                name,
			Subject:               name,
			NotBefore:             now,
			NotAfter:              now.Add(validity),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
			BasicConstraintsValid: true,
			DNSNames:              dnsName,
		}

		for _, str := range ipAddress {
			ip := net.ParseIP(str)
			if ip == nil {
				return fmt.Errorf("invalid IP address %q", str)
			}

			cert.IPAddresses = append(cert.IPAddresses, ip)
		}

		if serverAuth {
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		}

		if clientAuth {
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		}

		bytes, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey.Public(), privateKey)
		if err != nil {
			return fmt.Errorf("could not create certificate: %w", err)
		}

		out := os.Stdout
		if outputPath != "" {
			file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return fmt.Errorf("could not open output path: %w", err)
			}
			defer file.Close()

			out = file
		}

		err = pem.Encode(out, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: bytes,
		})
		if err != nil {
			return fmt.Errorf("could not marshal PEM-encoded certificate request: %w", err)
		}

		return nil
	},
}

func init() {
	genCSRflags(genCert.Flags())

	genCert.Flags().DurationVar(&validity, "validity", 8766*time.Hour, "relative expiry date of the certificate")
	genCert.Flags().BoolVar(&serverAuth, "server", false, "enable certificate for server authentication")
	genCert.Flags().BoolVar(&clientAuth, "client", false, "enable certificate for client authentication")
}

// randomSerialNumber generates a cryptographically secure random 16-byte
// number for use as the serial number of a certificate.
func randomSerialNumber() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}
