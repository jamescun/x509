package generate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	keyType  string
	keySize  int
	keyCurve string
)

var genKey = &cobra.Command{
	Use:   "key",
	Short: "generate private keys",

	PreRunE: func(cmd *cobra.Command, args []string) error {
		switch keyType {
		case "":
			return fmt.Errorf("--type is required")

		case "rsa", "RSA":
			keyType = "RSA"

			if keySize == 0 {
				return fmt.Errorf("--size is required for RSA keys")
			}

			if keySize < 1 || keySize > 8194 {
				return fmt.Errorf("unsupported RSA key size %d", keySize)
			}

		case "ecdsa", "ECDSA":
			keyType = "ECDSA"

			switch keyCurve {
			case "":
				return fmt.Errorf("--curve is required for ECDSA keys")

			case "224", "p224", "P224", "P-224":
				keyCurve = "P224"
			case "256", "p256", "P256", "P-256":
				keyCurve = "P256"
			case "384", "p384", "P384", "P-384":
				keyCurve = "P384"
			case "521", "p521", "P521", "P-521":
				keyCurve = "P521"

			default:
				return fmt.Errorf("unsupported ECDSA curve %q", keyCurve)
			}

		case "ed25519", "ED25519", "Ed25519":
			// no configuration possible for Ed25519
			keyType = "Ed25519"

		default:
			return fmt.Errorf("unknown key type %q", keyType)
		}

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var privateKey crypto.PrivateKey

		switch keyType {
		case "RSA":
			key, err := rsa.GenerateKey(rand.Reader, keySize)
			if err != nil {
				return fmt.Errorf("could not generate RSA private key: %w", err)
			}

			privateKey = key

		case "ECDSA":
			key, err := ecdsa.GenerateKey(getCurve(keyCurve), rand.Reader)
			if err != nil {
				return fmt.Errorf("could not generate ECDSA private key: %w", err)
			}

			privateKey = key

		case "Ed25519":
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("could not generate Ed25519 private key: %w", err)
			}

			privateKey = key
		}

		bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return fmt.Errorf("could not marshal PKCS#8 private key: %w", err)
		}

		out := os.Stdout
		if outputPath != "" {
			file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("could not open output path: %w", err)
			}
			defer file.Close()

			out = file
		}

		err = pem.Encode(out, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		})
		if err != nil {
			return fmt.Errorf("could not PEM-encode private key: %w", err)
		}

		return nil
	},
}

func init() {
	genKey.Flags().StringVar(&keyType, "type", "", "type of key to generate (rsa, ecdsa or ed25519)")
	genKey.Flags().IntVar(&keySize, "size", 2048, "size of key to generate (rsa only)")
	genKey.Flags().StringVar(&keyCurve, "curve", "P256", "elliptic curve of key to generate (ecdsa only)")
	genKey.Flags().StringVar(&outputPath, "output", "", "write private key to file instead of stdout")
}

func getCurve(curve string) elliptic.Curve {
	switch curve {
	case "P224":
		return elliptic.P224()
	case "P256":
		return elliptic.P256()
	case "P384":
		return elliptic.P384()
	case "P521":
		return elliptic.P521()

	default:
		return nil
	}
}
