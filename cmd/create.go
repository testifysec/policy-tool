package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"context"

	"github.com/in-toto/archivista/pkg/api"
	"github.com/in-toto/go-witness/policy"
	"gopkg.in/yaml.v2"
)

type searchResults struct {
	Dsses struct {
		Edges []struct {
			Node struct {
				GitoidSha256 string `json:"gitoidSha256"`
				Statement    struct {
					AttestationCollection struct {
						Name         string `json:"name"`
						Attestations []struct {
							Type string `json:"type"`
						} `json:"attestations"`
					} `json:"attestationCollections"`
				} `json:"statement"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"dsses"`
}

const searchQuery = `query($algo: String!, $digest: String!) {
	dsses(
	  where: {
		hasStatementWith: {
		  hasSubjectsWith: {
			hasSubjectDigestsWith: {
			  value: $digest,
			  algorithm: $algo
			}
		  }
		}
	  }
	) {
	  edges {
		node {
		  gitoidSha256
		  statement {
			attestationCollections {
			  name
			  attestations {
				type
			  }
			}
		  }
		}
	  }
	}
  }`

type searchVars struct {
	Algorithm string `json:"algo"`
	Digest    string `json:"digest"`
}

var archivistaURL *string

const archivistaUrl = "https://archivista.testifysec.io"

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

// fetchAttestations fetches attestations for given subjects from Archivista.
func fetchAttestations(subjects []string) ([]policy.Step, error) {
	var allSteps []policy.Step

	for _, subject := range subjects {
		algo, digest, err := validateDigestString(subject)
		if err != nil {
			return nil, fmt.Errorf("invalid subject %s: %v", subject, err)
		}

		// Assuming api.GraphQlQuery function and archivistaUrl are accessible here
		results, err := api.GraphQlQuery[searchResults](context.Background(), archivistaUrl, searchQuery, searchVars{Algorithm: algo, Digest: digest})
		if err != nil {
			return nil, fmt.Errorf("error fetching attestations for %s: %v", subject, err)
		}

		for _, edge := range results.Dsses.Edges {
			for _, attestation := range edge.Node.Statement.AttestationCollection.Attestations {
				// Convert each attestation result into your policy.Attestation struct
				// Note: You may need to adjust the conversion based on how your policy.Attestation is structured
				policyAttestation := policy.Attestation{
					Type: attestation.Type,
				}

				// Create a new step for each attestation
				step := policy.Step{
					Name:         edge.Node.Statement.AttestationCollection.Name,
					Attestations: []policy.Attestation{policyAttestation},
				}

				allSteps = append(allSteps, step)

			}
		}
	}

	return allSteps, nil
}

func parseArgs(args []string) (map[string]policy.Step, map[string][]string, error) {

	// Example: Determine commit hash from args - this logic may vary based on your command line design

	// Fetch attestations by subject
	subjects := []string{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-b") || strings.HasPrefix(arg, "--subjects") {
			arg = strings.TrimPrefix(strings.TrimPrefix(arg, "-b"), "--subjects")
			arg = strings.TrimPrefix(arg, "=")
			subjects = append(subjects, strings.Split(arg, ",")...)
		}
	}

	steps := make(map[string]policy.Step)

	for _, subject := range subjects {
		fmt.Printf("Fetching attestations for %s\n", subject)
		attestations, err := fetchAttestations([]string{subject})
		if err != nil {
			return nil, nil, err
		}

		for _, step := range attestations {
			steps[step.Name] = step
		}

	}

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

func extractKeyValues(attestations []struct {
	Type        string          `json:"type"`
	Attestation json.RawMessage `json:"attestation"`
}) (map[string]map[string]string, error) {
	keyValuePairs := make(map[string]map[string]string)

	for _, att := range attestations {
		var attData map[string]interface{}
		err := json.Unmarshal(att.Attestation, &attData)
		if err != nil {
			return nil, err
		}

		// Initialize the key value pair map for this attestation type
		keyValuePairs[att.Type] = make(map[string]string)

		for key, value := range attData {
			switch att.Type {
			case "https://witness.dev/attestations/material/v0.1":
				if hashData, ok := value.(map[string]interface{}); ok {
					if hash, ok := hashData["sha256"]; ok {
						keyValuePairs[att.Type][key] = hash.(string)
					}
				}
			case "https://witness.dev/attestations/product/v0.1":
				if hashData, ok := value.(map[string]interface{}); ok {
					if digest, ok := hashData["digest"].(map[string]interface{}); ok {
						if hash, ok := digest["sha256"]; ok {
							keyValuePairs[att.Type][key] = hash.(string)
						}
					}
				}
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

func validateDigestString(ds string) (algo, digest string, err error) {
	fmt.Println("ds", ds)

	algo, digest, found := strings.Cut(ds, ":")
	if !found {
		return "", "", errors.New("invalid digest string. expected algorithm:digest")
	}

	return algo, digest, nil
}
