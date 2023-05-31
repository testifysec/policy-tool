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
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/intoto"
	"github.com/testifysec/go-witness/policy"
	"gopkg.in/yaml.v2"
)

var archivistaURL *string

type parsedCollection struct {
	attestation.Collection
	Attestations []struct {
		Type        string          `json:"type"`
		Attestation json.RawMessage `json:"attestation"`
	} `json:"attestations"`
}

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

	//check to see if we have a dsse file or dsse archivista id
	hasDSSE := false

	for _, arg := range args {
		if strings.HasPrefix(arg, "-d") || strings.HasPrefix(arg, "-x") {
			hasDSSE = true
		}

		if strings.HasPrefix(arg, "--dsse") || strings.HasPrefix(arg, "--dsse-archivista") {
			hasDSSE = true
		}
	}

	//check to see if we have a step name flag
	hasStep := false

	for _, arg := range args {
		if strings.HasPrefix(arg, "-s") {
			hasStep = true
		}

		if strings.HasPrefix(arg, "--step") {
			hasStep = true

		}

	}

	if !hasStep && !hasDSSE {
		return errors.New("must provide a step name and a dsse file or dsse archivista id")
	}

	if hasStep && hasDSSE {
		return errors.New("cannot provide both a dsse file and a step name")
	}

	//raw is a lazy hack to get around the fact that we need to parse the args twice
	steps, raw, err := parseArgs(args)
	if err != nil {
		return err
	}

	roots, err := parseRoots(raw)
	if err != nil {
		return err
	}

	pubKeys, err := parsePublicKeys(raw)
	if err != nil {
		return err
	}

	tsas, err := parseTSA(raw)
	if err != nil {
		return err
	}

	p := &policy.Policy{
		Expires:              time.Now().Add(expires),
		Roots:                roots,
		TimestampAuthorities: createTimestampAuthorities(tsas),
		PublicKeys:           pubKeys,
		Steps:                steps,
	}

	policyBytes, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(policyBytes))
	return nil
}

// https://archivista.testifysec.io/download/354754c3452052ec52da4ecf2022257c4bf045f2b181b812162e012b6ad4b162
// function parses the attestationCollection from the file or url provides
func parseAttestationCollectionFromFile(filePath string) ([]policy.Attestation, *parsedCollection, error) {
	//lets get the bytes from the file or url first
	var b []byte

	if strings.HasPrefix(filePath, "http") {
		resp, err := http.Get(filePath)
		if err != nil {
			return nil, nil, err
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("failed to download attestation collection: %s", resp.Status)

		}

		b, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, err
		}

	} else {
		//read the file
		var err error
		b, err = ioutil.ReadFile(filePath)
		if err != nil {
			return nil, nil, err
		}
	}

	envelope := &dsse.Envelope{}
	if err := json.Unmarshal(b, envelope); err != nil {
		return nil, nil, err
	}

	payload := &intoto.Statement{}
	if err := json.Unmarshal(envelope.Payload, payload); err != nil {
		return nil, nil, err
	}

	parsedCollection := &parsedCollection{}
	if err := json.Unmarshal(payload.Predicate, parsedCollection); err != nil {
		return nil, nil, err
	}

	attestations := make([]policy.Attestation, 0, len(parsedCollection.Attestations))

	for _, a := range parsedCollection.Attestations {
		attestations = append(attestations, policy.Attestation{
			Type:         a.Type,
			RegoPolicies: []policy.RegoPolicy{},
		})
	}

	return attestations, parsedCollection, nil
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
	foundRoot := false

	for _, flag := range flags {

		switch {
		case strings.HasPrefix(flag, "-k") || strings.HasPrefix(flag, "--public-key"):
			if foundRoot {

				functionaries = append(functionaries, policy.Functionary{
					Type:           "root",
					CertConstraint: certConstraint,
				})
			}

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
			if foundRoot {

				functionaries = append(functionaries, policy.Functionary{
					Type:           "root",
					CertConstraint: certConstraint,
				})
			}

			foundRoot = true
			filePath := strings.TrimPrefix(strings.TrimPrefix(flag, "-r"), "--root-ca")
			filePath = strings.TrimSpace(strings.TrimPrefix(filePath, "="))

			cert, err := parseCertFromFile(filePath)
			if err != nil {
				return nil
			}

			h := sha256.Sum256(cert)
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

	}

	if foundRoot {

		functionaries = append(functionaries, policy.Functionary{
			Type:           "root",
			CertConstraint: certConstraint,
		})
	}

	return functionaries
}

func parseKeyFromFile(filePath string) (policy.PublicKey, error) {
	pk := policy.PublicKey{
		KeyID: "",
		Key:   []byte{},
	}

	// Read the file
	pubPEM, err := ioutil.ReadFile(filePath)
	if err != nil {
		return pk, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return pk, errors.New("failed to decode PEM block containing the public key")
	}

	// Parse the public key
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return pk, err
	}

	// keyid is the sha256 hash of the PEM
	h := sha256.Sum256(pubPEM)
	hexEncoded := hex.EncodeToString(h[:])
	pk.KeyID = hexEncoded
	pk.Key = pubPEM

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

func createTimestampAuthorities(tsas [][]byte) map[string]policy.Root {
	timestampAuthorities := make(map[string]policy.Root)

	for _, cert := range tsas {
		h := sha256.Sum256(cert)
		timestampAuthorities[hex.EncodeToString(h[:])] = policy.Root{
			Certificate: cert,
		}
	}

	return timestampAuthorities
}

func parseTSA(steps map[string][]string) ([][]byte, error) {
	var tsaCerts [][]byte

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
		var rootCert []byte
		intermediateCerts := [][]byte{}

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
			certSHA := sha256.Sum256(rootCert)
			certHash := hex.EncodeToString(certSHA[:])

			intermediates := [][]byte{}

			for _, intermediate := range intermediateCerts {
				intermediates = append(intermediates, intermediate)
			}

			roots[certHash] = policy.Root{
				Certificate:   rootCert,
				Intermediates: intermediates,
			}

		}
	}

	return roots, nil
}

func parseArgs(args []string) (map[string]policy.Step, map[string][]string, error) {
	steps := make(map[string]policy.Step)
	stepsTemp := make(map[string][]string)

	var currentStep string
	var currentCollection *parsedCollection

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case isStickyKeysFileFlag(arg):
			arg := strings.TrimPrefix(strings.TrimPrefix(arg, "-y"), "--sticky-keys")
			arg = strings.TrimPrefix(arg, "=")
			filepath := strings.TrimSpace(arg)

			if filepath == "" {
				i++
				if i < len(args) {
					filepath = args[i]
				} else {
					return nil, nil, fmt.Errorf("missing file path after %s", arg)
				}
			}

			stickyKeys := make(map[string][]string)

			file, err := os.Open(filepath)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to open sticky keys file %s: %v", filepath, err)
			}

			err = yaml.NewDecoder(file).Decode(&stickyKeys)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to unmarshal sticky keys file %s: %v", filepath, err)
			}

			regoModules, err := generateRegoModules(stickyKeys, currentCollection.Attestations)
			if err != nil {
				return nil, nil, err
			}

			//add the rego modules to the current step
			for key, module := range regoModules {
				// Base64 encode the rego module so it can be passed as a []byte
				// Make module string into a []byte
				modulebytes := []byte(module)

				attestation := policy.Attestation{
					Type:         key,
					RegoPolicies: []policy.RegoPolicy{{Module: modulebytes, Name: fmt.Sprintf("%s-%s", currentStep, key)}},
				}

				//find the attestation witht the same type as the current key
				//if it exists, append the rego policy to the existing attestation
				//if it doesn't exist, create a new attestation and append it to the step
				found := false

				for i, a := range steps[currentStep].Attestations {
					if a.Type == key {
						steps[currentStep].Attestations[i].RegoPolicies = append(steps[currentStep].Attestations[i].RegoPolicies, attestation.RegoPolicies[0])
						found = true
						break
					}
				}

				if !found {
					//just print an warning to std err and continue
					fmt.Fprintf(os.Stderr, "WARNING: no attestation found for type %s, skipping sticky keys for this attestation", key)
				}

			}

		case isDSSEFileFlag(arg):
			arg := strings.TrimPrefix(strings.TrimPrefix(arg, "-d"), "--dsse")
			arg = strings.TrimPrefix(arg, "=")
			filepath := strings.TrimSpace(arg)

			if filepath == "" {
				i++
				if i < len(args) {
					filepath = args[i]
				} else {
					return nil, nil, fmt.Errorf("missing file path after %s", arg)
				}
			}
			attestations, parsedCollection, err := parseAttestationCollectionFromFile(filepath)
			if err != nil {
				return nil, nil, err
			}

			stepName := parsedCollection.Name
			steps[stepName] = policy.Step{
				Attestations: attestations,
				Name:         stepName,
			}
			currentStep = stepName
			currentCollection = parsedCollection

		case isDSSEArchivistaFlag(arg):
			arg := strings.TrimPrefix(strings.TrimPrefix(arg, "-x"), "--dsse-archivista")
			//trim "=" and any whitespace from the beginning of the string
			arg = strings.TrimPrefix(arg, "=")
			arg = strings.TrimSpace(arg)
			url := *archivistaURL + arg

			if url == *archivistaURL {
				i++
				if i < len(args) {
					url = *archivistaURL + args[i]
				} else {
					return nil, nil, fmt.Errorf("missing Archivista URL path after %s", arg)
				}
			}
			attestations, parsedCollection, err := parseAttestationCollectionFromFile(url)
			if err != nil {
				return nil, nil, err
			}

			stepName := parsedCollection.Name

			steps[stepName] = policy.Step{
				Attestations: attestations,
				Name:         stepName,
			}
			currentStep = stepName
			currentCollection = parsedCollection

		case isStepFlag(arg):
			stepName, newIndex, err := parseStepFlag(args, i)
			if err != nil {
				return nil, nil, err
			}
			i = newIndex
			currentStep = stepName
			steps[currentStep] = policy.Step{}

		case strings.HasPrefix(arg, "-"):
			if currentStep == "" {
				return nil, nil, fmt.Errorf("argument %s is not bound to a step flag", arg)
			}
			flagWithValue, newIndex, err := parseFlagWithValue(args, i)
			if err != nil {
				return nil, nil, err
			}
			i = newIndex
			stepsTemp[currentStep] = append(stepsTemp[currentStep], flagWithValue)
		}
	}

	// Process temporary steps and merge them into main steps.
	for stepName, flags := range stepsTemp {
		tempStep := policy.Step{
			Attestations:  parseAttestationsFromFlags(flags),
			Functionaries: parseFunctionariesFromFlags(flags),
			Name:          stepName,
		}
		steps[stepName] = mergeSteps(steps[stepName], tempStep)
	}

	return steps, stepsTemp, nil
}

// Merge two steps, giving preference to the functionaries from step2 if they exist.
func mergeSteps(step1, step2 policy.Step) policy.Step {
	if step2.Functionaries != nil {
		step1.Functionaries = step2.Functionaries
	}
	if step2.Attestations != nil {
		step1.Attestations = step2.Attestations
	}
	return step1
}

func isStickyKeysFileFlag(arg string) bool {
	return strings.HasPrefix(arg, "-y") || strings.HasPrefix(arg, "--sticky-keys")
}

func isDSSEFileFlag(arg string) bool {
	return strings.HasPrefix(arg, "-d") || strings.HasPrefix(arg, "--dsse")
}

func isDSSEArchivistaFlag(arg string) bool {
	return strings.HasPrefix(arg, "-x") || strings.HasPrefix(arg, "--dsse-archivista")
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

func parseCertFromFile(filePath string) ([]byte, error) {
	cert := []byte{}
	var certData []byte
	var err error

	if strings.HasPrefix(filePath, "http://") || strings.HasPrefix(filePath, "https://") {
		resp, err := http.Get(filePath)
		if err != nil {
			return cert, fmt.Errorf("failed to fetch certificate from URL %s: %v", filePath, err)
		}
		defer resp.Body.Close()

		certData, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return cert, fmt.Errorf("failed to read certificate data from URL %s: %v", filePath, err)
		}
	} else {
		certData, err = ioutil.ReadFile(filePath)
		if err != nil {
			return cert, fmt.Errorf("failed to read certificate file %s: %v", filePath, err)
		}
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return cert, fmt.Errorf("failed to decode PEM block containing certificate in file %s", filePath)
	}

	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return cert, fmt.Errorf("failed to parse certificate from file %s: %v", filePath, err)
	}

	return certData, nil
}

func getNestedValue(jsonMap map[string]interface{}, path string) (interface{}, bool) {
	keys := strings.Split(path, ".")
	var currentValue interface{} = jsonMap

	for _, key := range keys {
		currentMap, ok := currentValue.(map[string]interface{})
		if !ok {
			return nil, false
		}
		currentValue, ok = currentMap[key]
		if !ok {
			return nil, false
		}
	}

	return currentValue, true
}

func generateRegoModules(stickyKeys map[string][]string, raw []struct {
	Type        string          `json:"type"`
	Attestation json.RawMessage `json:"attestation"`
}) (map[string]string, error) {
	keyValuePairs, err := extractKeyValues(stickyKeys, raw)
	if err != nil {
		return nil, err
	}
	regoModules, err := generateRegoModulesFromKeyValues(stickyKeys, keyValuePairs)
	if err != nil {
		return nil, err
	}
	return regoModules, nil
}

func extractKeyValues(stickyKeys map[string][]string, raw []struct {
	Type        string          `json:"type"`
	Attestation json.RawMessage `json:"attestation"`
}) (map[string]map[string]interface{}, error) {
	keyValuePairs := make(map[string]map[string]interface{})

	for _, s := range raw {
		a := make(map[string]interface{})
		err := json.Unmarshal(s.Attestation, &a)
		if err != nil {
			return nil, err
		}
		attestationType := s.Type
		if keys, ok := stickyKeys[attestationType]; ok {
			keyValuePairs[attestationType] = make(map[string]interface{})
			for _, key := range keys {
				value, ok := getNestedValue(a, key)
				if !ok {
					return nil, fmt.Errorf("key %s not found in attestation type %s", key, attestationType)
				}
				keyValuePairs[attestationType][key] = value
			}
		}
	}
	return keyValuePairs, nil
}

func generateRegoModulesFromKeyValues(stickyKeys map[string][]string, keyValuePairs map[string]map[string]interface{}) (map[string]string, error) {
	regoModules := make(map[string]string)

	for attestationType, keys := range stickyKeys {
		rules, err := generateRules(attestationType, keys, keyValuePairs)
		if err != nil {
			return nil, err
		}

		packageName := getPackageName(attestationType)
		regoModule := createRegoModule(packageName, rules, keys, attestationType)
		regoModules[attestationType] = regoModule
	}

	return regoModules, nil
}

func generateRules(attestationType string, keys []string, keyValuePairs map[string]map[string]interface{}) ([]string, error) {
	var rules []string

	for _, key := range keys {
		value := keyValuePairs[attestationType][key]
		rule, err := createRule(key, value, attestationType)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func createRule(key string, value interface{}, attestationType string) (string, error) {
	switch v := value.(type) {
	case string:
		return fmt.Sprintf(`input.%s != "%v"`, key, value), nil
	case []interface{}:
		quotedVals, err := stringifySlice(v)
		if err != nil {
			return "", fmt.Errorf("unexpected value type for key '%s' in attestation type '%s': expected string, got %T", key, attestationType, v)
		}
		return fmt.Sprintf(`input.%s != [%s]`, key, strings.Join(quotedVals, ",")), nil
	case int, int32, int64, float32, float64:
		return fmt.Sprintf(`input.%s != %v`, key, value), nil
	case bool:
		return fmt.Sprintf(`input.%s != %v`, key, value), nil
	default:
		return "", fmt.Errorf("unexpected value type for key '%s' in attestation type '%s': expected string, slice of strings, number, or boolean, got %T", key, attestationType, value)
	}
}

func stringifySlice(slice []interface{}) ([]string, error) {
	var quotedVals []string

	for _, elem := range slice {
		str, ok := elem.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected element type: expected string, got %T", elem)
		}
		quotedVals = append(quotedVals, fmt.Sprintf("%q", str))
	}

	return quotedVals, nil
}

func getPackageName(attestationType string) string {
	segments := strings.Split(attestationType, "/")
	packageName := segments[len(segments)-2]
	packageName = regexp.MustCompile("[^a-zA-Z0-9_]+").ReplaceAllString(packageName, "_")
	return packageName
}

func createRegoModule(packageName string, rules []string, keys []string, attestationType string) string {
	regoModuleTemplate := `package %s
	deny[msg] {
		%s
		msg := "unexpected value for key(s) %s in attestation type %s"
	}`

	return fmt.Sprintf(regoModuleTemplate, packageName, strings.Join(rules, "\n\t"), strings.Join(keys, ", "), attestationType)
}
