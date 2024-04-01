package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/in-toto/go-witness/policy"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

	expireTime := time.Now().Add(expires)
	t := v1.Time{Time: expireTime}

	p := &policy.Policy{
		Expires:              t,
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
