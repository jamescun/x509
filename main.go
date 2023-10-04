package main

import (
	"context"
	"os"

	"github.com/jamescun/x509/cli"
)

var (
	// Version is the semantic release of this build of x509.
	Version = "0.0.0"

	// Revision is the commit reference of Git at build time.
	Revision = "dev"
)

func main() {
	ctx := context.Background()

	cli.SetVersion(Version, Revision)

	if err := cli.Root().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
