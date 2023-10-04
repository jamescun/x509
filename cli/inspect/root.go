package inspect

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var root = &cobra.Command{
	Use:   "inspect object.pem",
	Short: "get details about PEM-encoded certificates, requests, private keys and more",

	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("inspect requires a file to read")
		} else if len(args) > 1 {
			return fmt.Errorf("inspect can only inspect one file at a time")
		}

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		bytes, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("could not read file to inspect: %w", err)
		}

		block, _ := pem.Decode(bytes)
		if block == nil {
			return fmt.Errorf("invalid PEM-encoded file")
		}

		switch block.Type {
		case "CERTIFICATE":
			err = inspectCert(os.Stdout, block.Bytes)

		case "CERTIFICATE REQUEST":
			err = inspectCSR(os.Stdout, block.Bytes)

		case "PRIVATE KEY", "EC PRIVATE KEY":
			err = inspectPrivateKey(os.Stdout, block.Bytes)

		default:
			return fmt.Errorf("unsupported file type %q", block.Type)
		}

		if err != nil {
			return fmt.Errorf("could not inspect %q: %w", block.Type, err)
		}

		return nil
	},
}

// Root returns the root of the inspect command line interface to be executed.
func Root() *cobra.Command {
	return root
}

// publicKeyFingerprint returns the SHA256 fingerprint of a public key.
func publicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	return sha256fingerprint(bytes), nil
}

// sha256fingerprint generates a SHA256 fingerprint for some bytes.
func sha256fingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}
