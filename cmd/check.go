package cmd

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/testifysec/go-witness/policy"
)

func CheckCmd() *cobra.Command {
	var policyFile string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check a policy file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := ReadPolicy(policyFile)
			if err != nil {
				return err
			}

			errors := CheckPolicy(p)

			if len(errors) > 0 {
				for _, err := range errors {
					fmt.Fprintln(os.Stderr, err)
				}
				return fmt.Errorf("policy check failed")
			}

			fmt.Println("Policy check passed")
			return nil
		},
	}

	cmd.Flags().StringVarP(&policyFile, "policy", "p", "", "path to policy file")

	err := cmd.MarkFlagRequired("policy")
	if err != nil {
		panic(err)
	}

	return cmd
}

func ReadPolicy(policyFile string) (*policy.Policy, error) {
	policyBytes, err := os.ReadFile(policyFile)
	if err != nil {
		return nil, err
	}

	p := &policy.Policy{}
	err = json.Unmarshal(policyBytes, p)
	if err != nil {
		return nil, err
	}

	return p, nil
}

//check the policy file

// CheckPolicy checks the policy file for correctness and expiration
func CheckPolicy(p *policy.Policy) []error {
	errors := []error{}

	// Make sure the policy is not expired
	if time.Now().After(p.Expires) {
		errors = append(errors, fmt.Errorf("policy expired"))
	}

	// Check that roots exist for all functionaries
	for _, step := range p.Steps {
		for _, functionary := range step.Functionaries {
			for _, fRoot := range functionary.CertConstraint.Roots {

				foundRoot := false
				for k, _ := range p.Roots {
					if fRoot == k {
						foundRoot = true
						break
					}
				}
				if !foundRoot {
					errors = append(errors, fmt.Errorf("error: Functionary '%s' for step '%s' not found in Roots.  Please make sure the root exists in the policy's 'Roots' slice", fRoot, step.Name))
				}
			}
		}
	}

	// Check root certificates
	for k, v := range p.Roots {

		cert, err := x509.ParseCertificate(v.Certificate)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' is not a valid x509 certificate: %v", k, err))
		}

		// Check that the root certificate is not expired
		if time.Now().After(cert.NotAfter) {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' is expired", k))
		}

		// Check that the root certificate is a CA
		if !cert.IsCA {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' is not a CA", k))
		}

		// Check that the root certificate has a valid signature
		err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' has an invalid signature: %v", k, err))
		}

		// Check that the root certificate has a valid public key
		err = cert.CheckSignatureFrom(cert)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' has an invalid public key: %v", k, err))
		}

		// check that the expiration date is not before the policy expiration date
		if cert.NotAfter.Before(p.Expires) {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' has an expiration date before the policy expiration date", k))
		}

		//if root has an intermediate, check that intermediate
		if len(v.Intermediates) > 0 {
			for _, intermediate := range v.Intermediates {

				// Check that the intermediate certificate is valid
				block, _ := pem.Decode([]byte(intermediate))
				if block == nil {
					errors = append(errors, fmt.Errorf("error: intermediate certificate '%s' is not a valid PEM block", k))
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					errors = append(errors, fmt.Errorf("error: intermediate certificate '%s' is not a valid x509 certificate: %v", k, err))
				}

				// Check that the intermediate certificate is not expired
				if time.Now().After(cert.NotAfter) {
					errors = append(errors, fmt.Errorf("error: intermediate certificate '%s' is expired", k))
				}

				// Check that the intermediate was signed by the root
				err = cert.CheckSignatureFrom(cert)
				if err != nil {
					errors = append(errors, fmt.Errorf("error: intermediate certificate '%s' was not signed by the root certificate", k))
				}
			}
		}
	}

	//check the timestamp authority
	for k, v := range p.TimestampAuthorities {
		// Check that the timestamp authority certificate is valid
		block, _ := pem.Decode([]byte(v.Certificate))
		if block == nil {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' is not a valid PEM block", k))
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' is not a valid x509 certificate: %v", k, err))
		}

		// Check that the timestamp authority certificate is not expired
		if time.Now().After(cert.NotAfter) {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' is expired", k))
		}

		// Check that the timestamp authority certificate is a CA
		if !cert.IsCA {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' is not a CA", k))
		}

		// Check that the timestamp authority certificate has a valid signature
		err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' has an invalid signature: %v", k, err))
		}

		// Check that the timestamp authority certificate has a valid public key
		err = cert.CheckSignatureFrom(cert)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' has an invalid public key: %v", k, err))
		}

		// Check that the timestamp authority certificate has a valid timestamp authority
		if cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' has an invalid timestamp authority", k))
		}

		// Check that the timestamp authority certificate has a valid timestamp authority
		if cert.KeyUsage != x509.KeyUsageDigitalSignature {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' has an invalid timestamp authority", k))
		}

		// check that the expiration date is not before the policy expiration date
		if cert.NotAfter.Before(p.Expires) {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' has an expiration date before the policy expiration date", k))
		}
	}
	return errors
}
