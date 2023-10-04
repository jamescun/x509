package generate

import (
	"github.com/spf13/cobra"
)

var root = &cobra.Command{
	Use:   "generate",
	Short: "generate can be used to initialize new private keys and certificate requests",
}

func init() {
	root.AddCommand(genCert)
	root.AddCommand(genCSR)
	root.AddCommand(genKey)
}

// Root returns the root of the generate command line interface to be executed.
func Root() *cobra.Command {
	return root
}
