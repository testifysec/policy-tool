// main.go
package main

import (
	"github.com/spf13/cobra"
	run "github.com/testifysec/policy-tool/cmd"
)

func main() {
	cmd := &cobra.Command{
		Use:   "policy-tool",
		Short: "Application for checking and creating witness policies",
	}

	cmd.AddCommand(run.CheckCmd())
	cmd.AddCommand(run.CreateCmd())

	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}
