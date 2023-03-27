package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateRegoModules(t *testing.T) {
	stickyKeys := map[string][]string{
		"attestationTypeA": {"keyA", "keyB"},
		"attestationTypeB": {"keyC", "keyD"},
	}
	raw := []struct {
		Type        string          `json:"type"`
		Attestation json.RawMessage `json:"attestation"`
	}{
		{
			Type: "attestationTypeA",
			Attestation: json.RawMessage(`{
                "keyA": "valueA",
                "keyB": "valueB"
            }`),
		},
		{
			Type: "attestationTypeB",
			Attestation: json.RawMessage(`{
                "keyC": "valueC",
                "keyD": "valueD"
            }`),
		},
	}

	expectedRegoModules := map[string]string{
		"attestationTypeA": `package attestationTypeA
deny[msg] {
    input.keyA != "valueA"
    input.keyB != "valueB"
    msg := "unexpected value for key(s) keyA,keyB in attestation type attestationTypeA"
}`,
		"attestationTypeB": `package attestationTypeB
deny[msg] {
    input.keyC != "valueC"
    input.keyD != "valueD"
    msg := "unexpected value for key(s) keyC,keyD in attestation type attestationTypeB"
}`,
	}

	actualRegoModules, err := generateRegoModules(stickyKeys, raw)
	require.NoError(t, err)

	for key, expected := range expectedRegoModules {
		expected = strings.TrimSpace(expected)
		expected = strings.ReplaceAll(expected, "\t", "    ")
		expected = strings.ReplaceAll(expected, ", ", ",")
		actual, ok := actualRegoModules[key]
		require.True(t, ok, "key not found in actual result: %s", key)
		actual = strings.TrimSpace(actual)
		actual = strings.ReplaceAll(actual, "\t", "    ")
		actual = strings.ReplaceAll(actual, ", ", ",")
		require.Equal(t, expected, actual, "unexpected result for key: %s", key)
	}
}
