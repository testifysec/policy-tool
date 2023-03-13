package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

type Attestation struct {
	Type string `json:"type"`
}

type CertConstraint struct {
	CommonName    string   `json:"commonname"`
	DNSNames      []string `json:"dnsnames"`
	Emails        []string `json:"emails"`
	Organizations []string `json:"organizations"`
	URIs          []string `json:"uris"`
	Roots         []string `json:"roots"`
}

type Functionary struct {
	Type           string         `json:"type"`
	CertConstraint CertConstraint `json:"certConstraint"`
}

type Step struct {
	Name          string        `json:"name"`
	Attestations  []Attestation `json:"attestations"`
	Functionaries []Functionary `json:"functionaries"`
}

type Policy struct {
	Expires              string          `json:"expires"`
	Steps                map[string]Step `json:"steps"`
	Roots                map[string]Root `json:"roots"`
	TimestampAuthorities map[string]TA   `json:"timestampauthorities"`
}

type Root struct {
	Certificate string `json:"certificate"`
}

type TA struct {
	Certificate string `json:"certificate"`
}

func main() {
	// open policy file defined as first argument
	policyFile := os.Args[1]
	policyFileBytes, err := ioutil.ReadFile(policyFile)
	if err != nil {
		log.Fatalf("Error reading policy file: %v", err)
	}

	// unmarshal policy file
	var policy Policy
	err = json.Unmarshal(policyFileBytes, &policy)
	if err != nil {
		log.Fatalf("Error parsing policy file: %v", err)
	}

	// make sure policy is not expired
	expiry, err := time.Parse(time.RFC3339, policy.Expires)
	if err != nil {
		log.Fatalf("Error parsing expiry time: %v", err)
	}

	if time.Now().After(expiry) {
		log.Fatal("Policy expired")
	}

	for i, root := range policy.Roots {
		pemBytes, err := base64.StdEncoding.DecodeString(root.Certificate)
		if err != nil {
			log.Fatalf("Error decoding certificate for root %d: %v", i, err)
		}

		// Decode the PEM-encoded certificate
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			log.Fatalf("Error decoding PEM block for root %d", i)
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("Error parsing certificate for root %d: %v", i, err)
		}

		// Print the certificate subject for verification
		fmt.Printf("Root %d Subject: %s\n", i, cert.Subject)
	}

	for i, root := range policy.TimestampAuthorities {
		pemBytes, err := base64.StdEncoding.DecodeString(root.Certificate)
		if err != nil {
			log.Fatalf("Error decoding certificate for root %d: %v", i, err)
		}

		// Decode the PEM-encoded certificate
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			log.Fatalf("Error decoding PEM block for root %d", i)
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("Error parsing certificate for root %d: %v", i, err)
		}

		// Print the certificate subject for verification
		fmt.Printf("Root %d Subject: %s\n", i, cert.Subject)
	}

	// output step information
	fmt.Printf("Parsed %d steps\n", len(policy.Steps))
	fmt.Printf("Parsed %d roots\n", len(policy.Roots))
}
