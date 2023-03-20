package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/testifysec/go-witness/policy"
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

	cmd.Flags().StringP("step", "s", "", "Step name to bind subsequent flags to (e.g., root CA, intermediate, attestations, Rego policy)")
	cmd.Flags().StringP("tsa-ca", "t", "", "Path to the TSA CA PEM file; should be used after a step flag")
	cmd.Flags().StringP("root-ca", "r", "", "Path to the root CA PEM file; should be used after a step flag")
	cmd.Flags().StringP("intermediate", "i", "", "Path to the intermediate PEM file (optional); should be used after a step flag")
	cmd.Flags().StringP("attestations", "a", "", "Attestations to include in the policy for a step; should be used after a step flag")
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

	cmd.MarkFlagRequired("step")

	//make sure we have either a root-ca or public-key, we need one or the other

	return cmd
}

func CreatePolicy(args []string, expires time.Duration) error {
	//check to make sure we have at least one rootca or public key
	hasKey := false

	for _, arg := range args {
		if strings.HasPrefix(arg, "-r") || strings.HasPrefix(arg, "-k") {
			hasKey = true
		}

		if strings.HasPrefix(arg, "--root-ca") || strings.HasPrefix(arg, "--public-key") {
			hasKey = true
		}
	}

	if !hasKey {
		return errors.New("must provide at least one root CA or public key")
	}

	steps, err := parseArgs(args)
	if err != nil {
		return err
	}

	roots, err := parseRoots(steps)
	if err != nil {
		return err
	}

	pubKeys, err := parsePublicKeys(steps)
	if err != nil {
		return err
	}

	tsas, err := parseTSA(steps)
	if err != nil {
		return err
	}

	p := &policy.Policy{
		Expires:              time.Now().Add(expires),
		Roots:                roots,
		TimestampAuthorities: createTimestampAuthorities(tsas),
		PublicKeys:           pubKeys,
		Steps:                createSteps(steps),
	}

	policyBytes, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(policyBytes))
	return nil
}

func parsePublicKeys(steps map[string][]string) (map[string]policy.PublicKey, error) {
	pubKeys := make(map[string]policy.PublicKey)

	for _, flags := range steps {
		for _, flag := range flags {
			switch {
			case strings.HasPrefix(flag, "-k") || strings.HasPrefix(flag, "--public-key"):

				filePath := strings.TrimPrefix(strings.TrimPrefix(flag, "-k"), "--public-key")
				filePath = strings.TrimSpace(strings.TrimPrefix(filePath, "="))

				k, err := parseKeyFromFile(filePath)
				if err != nil {
					return nil, err
				}
				pubKeys[k.KeyID] = k
			}
		}
	}
	return pubKeys, nil
}

func createSteps(steps map[string][]string) map[string]policy.Step {
	stepsMap := make(map[string]policy.Step)

	for stepName, flags := range steps {
		stepAttestations := parseAttestationsFromFlags(flags)
		stepFunctionaries := parseFunctionariesFromFlags(flags)
		stepsMap[stepName] = policy.Step{
			Name:          stepName,
			Functionaries: stepFunctionaries,
			Attestations:  stepAttestations,
			ArtifactsFrom: []string{},
		}
	}

	return stepsMap
}

func parseFunctionariesFromFlags(flags []string) []policy.Functionary {
	var functionaries []policy.Functionary

	certConstraint := policy.CertConstraint{
		CommonName:    "*",
		DNSNames:      []string{"*"},
		Emails:        []string{"*"},
		Organizations: []string{"*"},
		URIs:          []string{"*"},
		Roots:         []string{},
	}

	for _, flag := range flags {
		foundRoot := false
		switch {
		case strings.HasPrefix(flag, "-k") || strings.HasPrefix(flag, "--public-key"):

			filePath := strings.TrimPrefix(strings.TrimPrefix(flag, "-k"), "--public-key")
			filePath = strings.TrimSpace(strings.TrimPrefix(filePath, "="))

			key, err := parseKeyFromFile(filePath)
			if err != nil {
				return nil
			}

			functionaries = append(functionaries, policy.Functionary{
				Type:        "publickey",
				PublicKeyID: key.KeyID,
			})

		case strings.HasPrefix(flag, "-r") || strings.HasPrefix(flag, "--root-ca"):
			foundRoot = true
			filePath := strings.TrimPrefix(strings.TrimPrefix(flag, "-r"), "--root-ca")
			filePath = strings.TrimSpace(strings.TrimPrefix(filePath, "="))

			cert, err := parseCertFromFile(filePath)
			if err != nil {
				return nil
			}

			h := sha256.Sum256(cert.Raw)
			hexEncoded := hex.EncodeToString(h[:])
			certConstraint.Roots = append(certConstraint.Roots, hexEncoded)
		case strings.HasPrefix(flag, "--constraint-commonname"):
			certConstraint.CommonName = strings.TrimSpace(strings.TrimPrefix(flag, "--constraint-commonname="))
		case strings.HasPrefix(flag, "--constraint-dnsnames"):
			certConstraint.DNSNames = strings.Split(strings.TrimSpace(strings.TrimPrefix(flag, "--constraint-dnsnames=")), ",")
		case strings.HasPrefix(flag, "--constraint-emails"):
			certConstraint.Emails = strings.Split(strings.TrimSpace(strings.TrimPrefix(flag, "--constraint-emails=")), ",")
		case strings.HasPrefix(flag, "--constraint-organizations"):
			certConstraint.Organizations = strings.Split(strings.TrimSpace(strings.TrimPrefix(flag, "--constraint-organizations=")), ",")
		case strings.HasPrefix(flag, "--constraint-uris"):
			uriStrs := strings.Split(strings.TrimSpace(strings.TrimPrefix(flag, "--constraint-uris=")), ",")
			for _, uriStr := range uriStrs {
				u, err := url.Parse(uriStr)
				if err == nil {
					certConstraint.URIs = append(certConstraint.URIs, u.String())
				}
			}

		}

		if foundRoot {

			functionaries = append(functionaries, policy.Functionary{
				Type:           "root",
				CertConstraint: certConstraint,
			})
		}

	}

	return functionaries
}

func parseKeyFromFile(filePath string) (policy.PublicKey, error) {
	pk := policy.PublicKey{
		KeyID: "",
		Key:   []byte{},
	}

	// Read the file
	certPEM, err := ioutil.ReadFile(filePath)
	if err != nil {
		return pk, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return pk, errors.New("failed to decode PEM block containing the public key")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return pk, err
	}

	//keyid is the sha256 hash of the cert.raw
	h := sha256.Sum256(cert.Raw)
	hexEncoded := hex.EncodeToString(h[:])
	pk.KeyID = hexEncoded
	pk.Key = cert.Raw

	return pk, nil
}
func parseAttestationsFromFlags(flags []string) []policy.Attestation {
	var attestations []policy.Attestation
	var currentAttestation *policy.Attestation

	for _, flag := range flags {
		if strings.HasPrefix(flag, "-a") || strings.HasPrefix(flag, "--attestations") {
			attestation := strings.TrimPrefix(strings.TrimPrefix(flag, "-a"), "--attestations")
			attestation = strings.TrimSpace(strings.TrimPrefix(attestation, "="))

			// Append the current attestation to the slice if it has already been processed
			if currentAttestation != nil {
				attestations = append(attestations, *currentAttestation)
			}

			currentAttestation = &policy.Attestation{
				Type:         attestation,
				RegoPolicies: []policy.RegoPolicy{},
			}
		} else if strings.HasPrefix(flag, "-g") || strings.HasPrefix(flag, "--rego-policy") {
			if currentAttestation == nil {
				panic("rego policy flag must be preceded by an attestation flag")
			}

			filePath := strings.TrimPrefix(strings.TrimPrefix(flag, "-g"), "--rego-policy")
			filePath = strings.TrimSpace(strings.TrimPrefix(filePath, "="))

			regoPolicy, err := loadAndEncodeRegoPolicy(filePath)
			if err != nil {
				continue
			}

			currentAttestation.RegoPolicies = append(currentAttestation.RegoPolicies, policy.RegoPolicy{Name: filePath, Module: regoPolicy})
		}
	}

	// Append the current attestation to the slice if it has already been processed
	if currentAttestation != nil {
		attestations = append(attestations, *currentAttestation)
	}

	return attestations
}
func loadAndEncodeRegoPolicy(filePath string) ([]byte, error) {
	regoData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Rego policy file %s: %v", filePath, err)
	}

	encodedRegoPolicy := base64.StdEncoding.EncodeToString(regoData)

	return []byte(encodedRegoPolicy), nil
}

func createTimestampAuthorities(tsas []*x509.Certificate) map[string]policy.Root {
	timestampAuthorities := make(map[string]policy.Root)

	for _, cert := range tsas {
		h := sha256.Sum256(cert.Raw)
		timestampAuthorities[hex.EncodeToString(h[:])] = policy.Root{
			Certificate: cert.Raw,
		}
	}

	return timestampAuthorities
}

func parseTSA(steps map[string][]string) ([]*x509.Certificate, error) {
	var tsaCerts []*x509.Certificate

	for _, flags := range steps {
		for _, flag := range flags {
			if strings.HasPrefix(flag, "-t") || strings.HasPrefix(flag, "--tsa-ca") {
				filePath := strings.TrimPrefix(strings.TrimPrefix(flag, "-t"), "--tsa-ca")
				filePath = strings.TrimSpace(strings.TrimPrefix(filePath, "="))

				cert, err := parseCertFromFile(filePath)
				if err != nil {
					return nil, err
				}

				tsaCerts = append(tsaCerts, cert)
			}
		}
	}

	return tsaCerts, nil
}

// this function opens the pem encoded CA and intermediate files from the steps and parses them into a policy.TrustBundle with the key being the hex encoded sha256 hash of the certificate
func parseRoots(steps map[string][]string) (map[string]policy.Root, error) {
	roots := make(map[string]policy.Root)

	for _, flags := range steps {
		var rootCert *x509.Certificate
		intermediateCerts := []*x509.Certificate{}

		for _, flag := range flags {
			var filePath string
			if strings.HasPrefix(flag, "-r") || strings.HasPrefix(flag, "--root-ca") {
				filePath = strings.TrimPrefix(strings.TrimPrefix(flag, "-r"), "--root-ca")
			} else if strings.HasPrefix(flag, "-i") || strings.HasPrefix(flag, "--intermediate") {
				filePath = strings.TrimPrefix(strings.TrimPrefix(flag, "-i"), "--intermediate")
			} else {
				continue
			}

			filePath = strings.TrimSpace(strings.TrimPrefix(filePath, "="))

			cert, err := parseCertFromFile(filePath)
			if err != nil {
				return nil, err
			}

			if strings.HasPrefix(flag, "-r") || strings.HasPrefix(flag, "--root-ca") {
				rootCert = cert
			} else if strings.HasPrefix(flag, "-i") || strings.HasPrefix(flag, "--intermediate") {
				intermediateCerts = append(intermediateCerts, cert)
			}
		}

		if rootCert != nil {
			certSHA := sha256.Sum256(rootCert.Raw)
			certHash := hex.EncodeToString(certSHA[:])

			intermediates := [][]byte{}

			for _, intermediate := range intermediateCerts {
				intermediates = append(intermediates, intermediate.Raw)
			}

			roots[certHash] = policy.Root{
				Certificate:   rootCert.Raw,
				Intermediates: intermediates,
			}

		}
	}

	return roots, nil
}

// parseArgs function takes command line arguments and organizes them into a map where the keys are step names and the values are slices of flags belonging to those steps.
// Each flag will be bound to the previous step flag encountered in the command line arguments.
func parseArgs(args []string) (map[string][]string, error) {
	steps := make(map[string][]string)
	currentStep := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if isStepFlag(arg) {
			stepName, newIndex, err := parseStepFlag(args, i)
			if err != nil {
				return nil, err
			}
			i = newIndex
			currentStep = stepName
			steps[currentStep] = []string{}
		} else if strings.HasPrefix(arg, "-") {
			if currentStep == "" {
				return nil, fmt.Errorf("argument %s is not bound to a step flag", arg)
			}

			flagWithValue, newIndex, err := parseFlagWithValue(args, i)
			if err != nil {
				return nil, err
			}
			i = newIndex
			steps[currentStep] = append(steps[currentStep], flagWithValue)
		}
	}

	return steps, nil
}

func isStepFlag(arg string) bool {
	return strings.HasPrefix(arg, "-s") || strings.HasPrefix(arg, "--step")
}

func parseStepFlag(args []string, index int) (string, int, error) {
	arg := args[index]
	var stepName string

	if strings.Contains(arg, "=") {
		stepName = strings.TrimSpace(strings.Split(arg, "=")[1])
	} else {
		index++
		if index < len(args) {
			stepName = strings.TrimSpace(args[index])
		} else {
			return "", index, fmt.Errorf("missing step name after %s", arg)
		}
	}

	return stepName, index, nil
}

func parseFlagWithValue(args []string, index int) (string, int, error) {
	arg := args[index]
	var flagWithValue string

	if strings.Contains(arg, "=") {
		flagWithValue = arg
	} else {
		index++
		if index < len(args) {
			argValue := args[index]
			flagWithValue = arg + "=" + argValue
		} else {
			return "", index, fmt.Errorf("missing value for flag %s", arg)
		}
	}

	return flagWithValue, index, nil
}

func parseCertFromFile(filePath string) (*x509.Certificate, error) {
	var certData []byte
	var err error

	if strings.HasPrefix(filePath, "http://") || strings.HasPrefix(filePath, "https://") {
		resp, err := http.Get(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch certificate from URL %s: %v", filePath, err)
		}
		defer resp.Body.Close()

		certData, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate data from URL %s: %v", filePath, err)
		}
	} else {
		certData, err = ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file %s: %v", filePath, err)
		}
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate in file %s", filePath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from file %s: %v", filePath, err)
	}

	return cert, nil
}
