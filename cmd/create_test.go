package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateSteps(t *testing.T) {
	args := []string{
		"-s", "step1",
		"-r", "testdata/root_ca.pem",
		"-a", "attestation1",
		"-g", "testdata/rego1.rego",
		"-a", "attestation2",
		"-g", "testdata/rego2.rego",
		"-s", "step2",
		"-r", "testdata/root_ca2.pem",
		"-a", "attestation3",
		"-g", "testdata/rego3.rego",
		"-a", "attestation4",
		"-g", "testdata/rego4.rego",
	}
	steps, err := parseArgs(args)
	require.NoError(t, err)

	createdSteps := createSteps(steps)
	require.Len(t, createdSteps, 2)

	step1, ok1 := createdSteps["step1"]
	require.True(t, ok1)

	step2, ok2 := createdSteps["step2"]
	require.True(t, ok2)

	require.Equal(t, "step1", step1.Name)
	require.Equal(t, "step2", step2.Name)

}

func TestCreateStepsEmpty(t *testing.T) {
	steps := make(map[string][]string)
	createdSteps := createSteps(steps)
	require.Len(t, createdSteps, 0)
}
