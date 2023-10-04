package generate

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	keyPath    string
	country    []string
	org        []string
	orgUnit    []string
	state      []string
	locality   []string
	commonName string
	dnsName    []string
	ipAddress  []string
	outputPath string
)

var genCSR = &cobra.Command{
	Use:   "csr",
	Short: "generate a certificate signing request (CSR)",

	Aliases: []string{
		"request",
	},

	PreRunE: func(cmd *cobra.Command, args []string) error {
		if keyPath == "" {
			return fmt.Errorf("--key is required")
		}

		if commonName == "" {
			return fmt.Errorf("--common-name is required")
		}

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		privateKey, err := readPrivateKey(keyPath)
		if err != nil {
			return fmt.Errorf("could not read private key: %w", err)
		}

		csr := &x509.CertificateRequest{
			Version: 3,
			Subject: pkix.Name{
				Country:            country,
				Organization:       org,
				OrganizationalUnit: orgUnit,
				Province:           state,
				Locality:           locality,
				CommonName:         commonName,
			},
			DNSNames: dnsName,
		}

		for _, str := range ipAddress {
			ip := net.ParseIP(str)
			if ip == nil {
				return fmt.Errorf("invalid IP address %q", str)
			}

			csr.IPAddresses = append(csr.IPAddresses, ip)
		}

		bytes, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		if err != nil {
			return fmt.Errorf("could not create certificate request: %w", err)
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
			Type:  "CERTIFICATE REQUEST",
			Bytes: bytes,
		})
		if err != nil {
			return fmt.Errorf("could not marshal PEM-encoded certificate request: %w", err)
		}

		return nil
	},
}

func genCSRflags(flagset *pflag.FlagSet) {
	flagset.StringVar(&keyPath, "key", "key.pem", "path to private key for certificate")
	flagset.StringArrayVar(&country, "country", nil, "the country for the certificate subject (C)")
	flagset.StringArrayVar(&org, "org", nil, "the organization for the certificate subject (O)")
	flagset.StringArrayVar(&orgUnit, "org-unit", nil, "the organization unit for the certificate subject (OU)")
	flagset.StringArrayVar(&state, "state", nil, "the state or province for the certificate subject (ST)")
	flagset.StringArrayVar(&locality, "locality", nil, "the locality for the certificate subject (L)")
	flagset.StringVar(&commonName, "common-name", "", "the common name for the certificate subject (CN)")
	flagset.StringArrayVar(&dnsName, "dns-name", nil, "additional dns names to embed in the certificate")
	flagset.StringArrayVar(&ipAddress, "ip-address", nil, "additional ip addresses to embed in the certificate")
	flagset.StringVar(&outputPath, "output", "", "write to file instead of stdout")
}

func init() {
	genCSRflags(genCSR.Flags())
}

func readPrivateKey(path string) (crypto.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM-encoded file")
	} else if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected PEM-encoded PKCS#8 PRIVATE KEY, got %q", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid PKCS# private key: %w", err)
	}

	return key, nil
}
