package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func CreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a policy file",
		Long: `create -s <step1_name> -r <root_ca_path> -a <attestation> -g <rego_path> -a <attestation> -g <rego_path> \
-s <step2_name> -r <root_ca_path> -a <attestation> -g <rego_path> -a <attestation> -g <rego_path> \
-o <output_path> -e <expiration> -t <tsa_ca_path>
					  
Flags must come after the step they are bound to. For example, the -r flag must come after the -s flag.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			expires, _ := cmd.Flags().GetDuration("expires")

			err := CreatePolicy(os.Args[2:], expires)
			if err != nil {
				return fmt.Errorf("policy creation failed: %v", err)
			}
			return nil
		},
	}

	archivistaURL = cmd.Flags().StringP("archivsita-url", "u", "https://archivista.testifysec.io/download/", "URL of the Archivista instance to use for DSSE envelope retrieval")
	cmd.Flags().StringP("dsse", "d", "", "Path to a DSSE envelope file to associate with an functionary, should be used instread of a step flag")
	cmd.Flags().StringP("dsse-archivista", "x", "", "gitoid of the DSSE envelope in Archivista; should be used instead of a step flag")
	cmd.Flags().StringP("sticky-keys", "y", "", "Path to a file containing a list of sticky keys to use for the policy")
	cmd.Flags().StringP("step", "s", "", "Step name to bind subsequent flags to (e.g., root CA, intermediate, attestations, Rego policy)")
	cmd.Flags().StringP("tsa-ca", "t", "", "Path to the TSA CA PEM file; should be used after a step flag")
	cmd.Flags().StringP("root-ca", "r", "", "Path to the root CA PEM file; should be used after a step flag")
	cmd.Flags().StringP("intermediate", "i", "", "Path to the intermediate PEM file (optional); should be used after a step flag")
	cmd.Flags().StringP("attestations", "a", "", "Attestations to include in the policy for a step; should be used after a step flag")
	cmd.Flags().StringP("subjects", "b", "", "Subjects to search for attestation to generate the policy")

	cmd.Flags().StringP("rego", "g", "", "Path to a Rego policy file to associate with an attestation; should be used after an attestation flag")
	cmd.Flags().StringP("public-key", "k", "", "Path to a public key file to associate with an attestation; should be used after a step flag")

	//flags for cert constraints
	cmd.Flags().String("constraint-commonname", "", "Certificate common name constraint")
	cmd.Flags().String("constraint-dnsnames", "", "Certificate DNS names constraint (comma-separated)")
	cmd.Flags().String("constraint-emails", "", "Certificate emails constraint (comma-separated)")
	cmd.Flags().String("constraint-organizations", "", "Certificate organizations constraint (comma-separated)")
	cmd.Flags().String("constraint-uris", "", "Certificate URIs constraint (comma-separated)")
	cmd.Flags().StringP("output", "o", "", "Output file to save the policy (default id stdout)")
	cmd.Flags().DurationP("expires", "e", time.Hour*24, "Expiration duration for the policy (e.g., 24h, 7d)")

	//make sure we have either a root-ca or public-key, we need one or the other

	return cmd
}
