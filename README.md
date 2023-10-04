# x509

x509 is a command line swiss army knife for working with SSL/TLS certificates.

It is intended as a modern, easier to use, interface than OpenSSL for common operations.

## Install

Either [download a pre-compiled binary](https://github.com/jamescun/x509/releases), or build from source:

```sh
go install github.com/jamescun/x509@latest
```

## Usage

As a command line interface, x509 utilizes sub-commands under the parent `x509` command. These are

* `inspect`, used to examine Certificates, Certificate Signing Requests, Private Keys, Public Keys and more.
* `generate`, used to create Private Keys, Certificate Signing Requests and Self-Signed Certificates.

## Examples

### Generating Private Keys

x509 can generate RSA, ECDSA and Ed25519 private keys.

To generate an ECDSA private key with the P-256 curve, run:

```sh
x509 generate key --type ecdsa --curve P-256
```

To generate an Ed25519 private key and write it to a file called `key.pem`, run:

```sh
x509 generate key --type ed25519 --output key.pem
```

### Generating Certificate Signing Requests

x509 can generate Certificate Signing Requests (CSRs) for existing private keys, to be given to a Certificate Authority to generate you a signed certificate.

To generate a Certificate Signing Request (CSR) from the private key `key.pem` for the ACME Limited company of Great Britain, and the DNS domains example.org and www.example.org, run:

```sh
x509 generate csr --key key.pem --country GB --org "ACME Limited" --common-name example.org --dns-name example.org --dns-name www.example.org
```

This command also supports the `--output` command line flag to write the CSR to a file instead of your console.

### Generating Self-Signed Certificates

Similarly to generating a Certificate Signing Request (CSR), x509 can self sign and issue certificates using the same arguments as `csr`.

Likewise to generate a self-signed certificate from the private key `key.pem` for the ACME Limited company of Great Britain, and the DNS domains example.org and www.example.org, run:

```sh
x509 generate cert --key key.pem --country GB --org "ACME Limited" --common-name example.org --dns-name example.org --dns-name www.example.org
```

The self-signed certificate will be outputted to your console, or can be written to a file using the `--output` command line flag.

### Inspect Certificates, Certificate Signing Requests and Private Keys

The `inspect` sub-command is able to read many different types of PEM-encoded file formats, such as Certificates, Certificate Signing Requests and Private Keys.

Pass the name of the file you wish to inspect, i.e. `cert.pem`, and metadata about the file will be outputted to your console:

```sh
x509 inspect cert.pem
```
