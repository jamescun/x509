package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	csr        string
	caCert     string
	caKey      string
	validity   time.Duration
	isCA       bool
	serverAuth bool
	clientAuth bool
	outputPath string
)

var root = &cobra.Command{
	Use:   "sign",
	Short: "sign a certificate signing request with a certificate authority",

	RunE: func(cmd *cobra.Command, args []string) error {
		csr, err := readCSR(csr)
		if err != nil {
			return fmt.Errorf("could not read csr: %w", err)
		}

		cert, err := readCertificate(caCert)
		if err != nil {
			return fmt.Errorf("could not read ca certificate: %w", err)
		}

		privateKey, err := readPrivateKey(caKey)
		if err != nil {
			return fmt.Errorf("could not read ca private key: %w", err)
		}

		serialNumber, err := randomSerialNumber()
		if err != nil {
			return fmt.Errorf("could not generate random serial number: %w", err)
		}

		now := time.Now()

		tpl := &x509.Certificate{
			Version:               1,
			SerialNumber:          serialNumber,
			Issuer:                cert.Issuer,
			Subject:               csr.Subject,
			NotBefore:             now,
			NotAfter:              now.Add(validity),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
			BasicConstraintsValid: true,
			DNSNames:              csr.DNSNames,
			IPAddresses:           csr.IPAddresses,
		}

		if isCA {
			tpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}

		if serverAuth {
			tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		}

		if clientAuth {
			tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		}

		bytes, err := x509.CreateCertificate(rand.Reader, tpl, cert, csr.PublicKey, privateKey)
		if err != nil {
			return fmt.Errorf("could not sign certificate: %w", err)
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
			return fmt.Errorf("could not marshal PEM-encoded certificate: %w", err)
		}

		return nil
	},
}

func init() {
	root.Flags().StringVar(&csr, "csr", "csr.pem", "path to certificate signing request to sign")
	root.Flags().StringVar(&caCert, "ca-cert", "ca.pem", "path to certificate authority certificate")
	root.Flags().StringVar(&caKey, "ca-key", "key.pem", "path to certificate authority private key")
	root.Flags().DurationVar(&validity, "validity", 8766*time.Hour, "relative expiry date of the certificate")
	root.Flags().BoolVar(&isCA, "ca", false, "enable certificate as certificate authority")
	root.Flags().BoolVar(&serverAuth, "server", false, "enable certificate for server authentication")
	root.Flags().BoolVar(&clientAuth, "client", false, "enable certificate for client authentication")
	root.Flags().StringVar(&outputPath, "output", "", "write signed certificate to file instead of console")
}

func readPrivateKey(path string) (crypto.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM-encoded file")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PKCS#8 private key: %w", err)
		}

		return key, nil

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid EC private key: %w", err)
		}

		return key, nil

	default:
		return nil, fmt.Errorf("unknown private key type %q", block.Type)
	}
}

func readCertificate(path string) (*x509.Certificate, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM-encoded file")
	} else if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected PEM-encoded certificate, got %q", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X.509 certificate: %w", err)
	}

	return cert, nil
}

func readCSR(path string) (*x509.CertificateRequest, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM-encoded file")
	} else if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected PEM-encoded certificate request, got %q", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X.509 certificate request: %w", err)
	}

	return csr, nil
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

// Root returns the root of the sign command line interface to be executed.
func Root() *cobra.Command {
	return root
}
