# [Witness](http://github.com/testifysec/witness) Policy Tool

The Witness Policy Tool is a command-line utility designed to create, and validate Witness policies. These policies play a crucial role in maintaining the integrity and security of your software development lifecycle (SDLC) by requiring the presence of specific attestations and values throughout every stage. To learn more about Witness, visit its [GitHub repository](http://github.com/testifysec/witness) , and for further information on policies, consult the [Witness policy documentation](https://github.com/testifysec/witness/blob/main/docs/policy.md) .

## Download

You can download the latest linux x64 release of `policy-tool` from [GitHub](https://github.com/testifysec/policy-tool/releases/download/v0.1.14/policy-tool).

If you need support for other arch/platforms please compile from source

## Usage
The tool is run from the command line and supports various commands and flags to create, and check, [Witness](http://github.com/testifysec/witness) policies. The check command allows you to validate an unsigned policy file, while the create command helps you create a new policy file with specific attestations, steps, and constraints.

To generate a [Witness](http://github.com/testifysec/witness) policy from existing attestations, you can instrument your pipeline with [Witness](http://github.com/testifysec/witness) and retrieve the gitoids for the attestations generated at each step. You can then pass these gitoids, along with the necessary CA certificates, to the policy tool to generate your policy.

Additionally, the tool includes a Rego Module Generator that helps you create Rego modules for validating attestation data based on key-value pairs provided in a YAML configuration file.

#### Check Command

The tool is run from the command line and takes the unsigned policy file as its only argument. For example:

```policy-tool check unsigned_policy_file.json```

The tool will output the following information:

- The steps in the policy file and the attestations associated with each step
- The decoded Rego policy module for each attestation
- The roots used in the policy file and the subject of each root's certificate
- The number of steps and roots parsed from the policy file

If there are any errors in the policy file, the tool will output a detailed error message with information about the error, including the step and attestation where the error occurred.

## Generating Policy From Existing Attestations

The policy tool supports generating attestations from attestation collections.  The user should instrument their pipeline with [Witness](http://github.com/testifysec/witness) and take
note of all of the gitoids for the attestations generated at each step.  If the user is not using [Archivista](http://github.com/testifysec/archivista) they should manually download all of the envelopes to pass into the tool

ex [Witness](http://github.com/testifysec/witness) log message
`level=info msg="Stored in [Archivista](http://github.com/testifysec/archivista) as e03b606faa2522f5262fcaf8c014f85972f22b2ce669692d2d0706aee493cdd2\n"`

The identifier is `e03b606faa2522f5262fcaf8c014f85972f22b2ce669692d2d0706aee493cdd2`


```
SAST=ff6c90ec2b0525df2d365115b84550a8d9df510a1a0bc1a01273363fda4a6e29
TEST=3366cec6c729723072b8cd8675514fe2b834abe9b5014c4bf262494242b30f8d
BUILD=e03b606faa2522f5262fcaf8c014f85972f22b2ce669692d2d0706aee493cdd2
```

You will need to pass in the CAs used for signing the attestations either as a URL or a file

```
CERT="./CA/ca.crt"
TSA_CERT="https://freetsa.org/files/cacert.pem"
```

Sticky values allow policy writers to specify certain key-value pairs in attestation documents that should be enforced in all subsequent evaluations. The idea behind sticky values is that they capture the properties of the input that should not change over time, and thus should be consistently enforced across all policy decisions.

We need to create a document specifying what are "sticky values are"

```sticky.yaml
https://witness.dev/attestations/gitlab/v0.1:
  - jwt.claims.project_id
  - jwt.claims.iss
  - ciconfigpath
  - jwt.verifiedBy.jwksUrl

https://witness.dev/attestations/gcp-iit/v0.1:
  - jwt.claims.iss
  - jwt.claims.aud
  - jwt.claims.email
  - jwt.claims.sub
  - jwt.verifiedBy.jwksUrl  

  - project_id
  - project_number
  - cluster_name
  - cluster_uid
  - cluster_location
  - zone

https://witness.dev/attestations/command-run/v0.1:
  - cmd
```

Now we can run the policy tool to generate our [Witness](http://github.com/testifysec/witness) Policy

`policy-tool create -x $SAST -y sticky.yaml -r $CERT -x $TEST -r $CERT -y sticky.yaml -x $BUILD -r $CERT -y sticky.yaml -t $TSA_CERT > policy.json`

Now you can ensure the policy is valid, `check` does some basic checks on the policy to make sure the certs are not expired and it is formated correctly

`policy-tool check -p policy.json`

This policy is now ready for review, signing, and deployment.

## Examples Using Command Line Provided Info

### Simple example

```bash
create --step test -r /path/to/root.pem --attestations https://witness.dev/attestations/commandrun/v0.1
```

This command creates a policy file with a root certificate located at `/path/to/root.pem` and an acommandRun attestation. The policy file will contain a single step named `test`.

### Complex example

```bash
policy-tool create \
                   ##Step1 \
                   -s step1 \
                   -r /path/to/root.pem \
                   -i /path/to/intermediate.pem \
                   -a https://witness.dev/attestations/aws/v0.1 \
                   -g /path/to/rego/file.rego \
                   -a https://witness.dev/attestations/commandrun/v0.1 \
                   -g /path/to/rego/file.rego \
                   ##Step2 \
                   -s step2 \
                   -i /path/to/intermediate.pem \
                   -a https://witness.dev/attestations/aws/v0.1 \
                   -a https://witness.dev/attestations/commandrun/v0.1 \
                   -g /path/to/rego/file.rego
```

This is an example command for using the policy-tool to create a complex [Witness](http://github.com/testifysec/witness) policy with multiple steps.

The command starts with policy-tool create, indicating that the create command should be used to generate a new policy. Then, it defines two steps using the -s flag: step1 and step2. For each step, it specifies the intermediate certificate using -i, and the attestations using -a. In step 1, two attestations are specified, along with the path to a Rego policy file (-g) for each attestation. Step 2 also has two attestations, but only one Rego policy file is used for both.

Each line in the command corresponds to a separate flag or parameter for the create command. The use of the backslash character (\) at the end of each line indicates that the command continues onto the next line for readability purposes.

The final policy file generated by this command would contain two steps, with the specified intermediate certificate, attestations, and associated Rego policy files for each step.

## Create Command

`create` - Creates a policy file.

### Flags

```bash
  -u, --archivsita-url string             URL of the [Archivista](http://github.com/testifysec/archivista) instance to use for DSSE envelope retrieval (default "https://archivista.testifysec.io/download/")
  -a, --attestations string               Attestations to include in the policy for a step; should be used after a step flag
      --constraint-commonname string      Certificate common name constraint
      --constraint-dnsnames string        Certificate DNS names constraint (comma-separated)
      --constraint-emails string          Certificate emails constraint (comma-separated)
      --constraint-organizations string   Certificate organizations constraint (comma-separated)
      --constraint-uris string            Certificate URIs constraint (comma-separated)
  -d, --dsse string                       Path to a DSSE envelope file to associate with an functionary, should be used instread of a step flag
  -x, --dsse-[Archivista](http://github.com/testifysec/archivista) string            gitoid of the DSSE envelope in Archivista; should be used instead of a step flag
  -e, --expires duration                  Expiration duration for the policy (e.g., 24h, 7d) (default 24h0m0s)
  -h, --help                              help for create
  -i, --intermediate string               Path to the intermediate PEM file (optional); should be used after a step flag
  -o, --output string                     Output file to save the policy (default id stdout)
  -k, --public-key string                 Path to a public key file to associate with an attestation; should be used after a step flag
  -g, --rego string                       Path to a Rego policy file to associate with an attestation; should be used after an attestation flag
  -r, --root-ca string                    Path to the root CA PEM file; should be used after a step flag
  -s, --step string                       Step name to bind subsequent flags to (e.g., root CA, intermediate, attestations, Rego policy)
  -y, --sticky-keys string                Path to a file containing a list of sticky keys to use for the policy
  -t, --tsa-ca string                     Path to the TSA CA PEM file; should be used after a step flag
  ```
### Notes

- The tool requires that the `--root-ca` or `--public-key` and `--attestations` flags are used at least once.
- Flags should be used after a step flag, which binds the flags to a specific step in the policy file. 
- The Rego policy file specified with the `--rego` flag is encoded as a base64 string in the policy file.

## Check Command

`check` - Checks a policy file

### Flags

```bash
  -p, --policy string   path to policy file
```


## Rego Module Generator Details

This utility generates Rego modules for validating attestation data based on a set of key-value pairs provided in a YAML configuration file. Attestations are used to prove the integrity of data, and this generator will create Rego modules with OPA (Open Policy Agent) rules to validate the provided attestation JSON.

### YAML Configuration

The input YAML file should list the attestation types as keys, with their corresponding required keys as an array of strings. Below is an example of the YAML configuration format:

```
https://witness.dev/attestations/gitlab/v0.1:
  - jwt.claims.project_id
  - jwt.claims.iss
  - ciconfigpath
  - jwt.verifiedBy.jwksUrl

https://witness.dev/attestations/gcp-iit/v0.1:
  - jwt.claims.iss
  - jwt.claims.aud
  - jwt.claims.email
  - jwt.claims.sub
  - jwt.verifiedBy.jwksUrl
  - project_id
  - project_number
  - cluster_name
  - cluster_uid
  - cluster_location
  - zone

https://witness.dev/attestations/command-run/v0.1:
  - cmd
  ```

### Limitations

#### Types

The `createRule` function in the generator has some limitations in handling the types of keys in the attestation data. Currently, it supports two key value types:


1. String: A single string value can be used as a key value. The generated Rego rule will check if the input key value is not equal to the provided string value.

1. Slice of strings: A slice of strings can also be used as a key value. In this case, the generated Rego rule will check if the input key value is not equal to the entire slice of strings.

1. Number: Any number type (int, int32, int64, float32, float64, etc.) can be used as a key value. The generated Rego rule will check if the input key value is not equal to the provided number value.

1. Bool: A boolean value can be used as a key value. The generated Rego rule will check if the input key value is not equal to the provided boolean value.

#### Nested Structures
The generator does not support complex nested structures such as maps or nested slices. If your attestation data contains keys with nested structures, you will need to extend the createRule function to handle these cases and generate appropriate Rego rules.

#### Complex Validation Logic
The generated Rego rules only perform basic validation, such as checking for value inequality. If your use case requires more complex validation logic, such as value ranges, regular expressions, or custom predicates, you may need to manually create rego policies and add them to the policy.