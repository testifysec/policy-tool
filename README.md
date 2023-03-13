# Witness Policy Checker

This is a policy checker for [Witness](https://github.com/testifysec/witness) policies. The tool reads in a **unsigned** JSON-encoded policy file and performs various checks to verify that the policy is valid.

## Download

You can download the latest linux x64 release of `policy-tool` from [GitHub](https://github.com/testifysec/policy-tool/releases/download/v0.1.14/policy-tool).

If you need support for other arch/platforms please compile from source


## Usage

The tool is run from the command line and takes the unsigned policy file as its only argument. For example:

```policy-tool unsigned_policy_file.json```

The tool will output the following information:

- The steps in the policy file and the attestations associated with each step
- The decoded Rego policy module for each attestation
- The roots used in the policy file and the subject of each root's certificate
- The number of steps and roots parsed from the policy file

If there are any errors in the policy file, the tool will output a detailed error message with information about the error, including the step and attestation where the error occurred.

Contributing
Contributions to the Witness Policy Checker are welcome. If you find a bug or would like to suggest an improvement, please submit a pull request with your changes.

License
The Witness Policy Checker is licensed under the Apache 2.0