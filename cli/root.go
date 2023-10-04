package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jamescun/x509/cli/generate"
	"github.com/jamescun/x509/cli/inspect"
)

var root = &cobra.Command{
	Use:   "x509 command",
	Short: "x509 is a modern interface to manage SSL/TLS certificates",
}

func init() {
	root.AddCommand(generate.Root())
	root.AddCommand(inspect.Root())
}

// SetVersion overwrites the Version on the Root of the CLI with a subcommand
// that prints version and build information.
func SetVersion(version, revision string) {
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "display version information",

		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "Version:  %s\nRevision: %s\n", version, revision)
		},
	})
}

// Root returns the root of the command line interface to be executed.
func Root() *cobra.Command {
	return root
}
