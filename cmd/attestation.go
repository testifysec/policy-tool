package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/policy"
)

type parsedCollection struct {
	attestation.Collection
	Attestations []struct {
		Type        string          `json:"type"`
		Attestation json.RawMessage `json:"attestation"`
	} `json:"attestations"`
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
