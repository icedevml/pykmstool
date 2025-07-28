# Google Cloud KMS Certificate Signing Request (CSR) Generation Tool

## Features

* List KMS key resource names within a specified region ID and/or project ID.
* Get PEM-encoded public key for a given KMS key.
* Generate CSR and sign it using KMS key.
  * Supports RSA (2048-4096, SHA256/SHA512), ECDSA (P-256, P-384, Secp256k1) and Ed25519 keys.
  * Automatically warns about possible compliance issues if the specified key is not HSM-protected or was imported
    (can be bypassed).
  * Subject X.509 name in the CSR is customized using RFC4514 string provided by the user.

## Classic usage

### Installation

1. Clone this repository.
2. Create a virtual environment and install required dependencies:
    ```
    python3 -m venv venv
    source venv/bin/activate
    pip3 install -r requirements.txt
    ```

### GCP Authentication

1. Install the [gcloud CLI](https://cloud.google.com/sdk/docs/install)
2. Create application default credentials:
   ```
   gcloud auth application-default login
   ```

> [!TIP]
> Alternatively, you can manually specify a service account JSON key file by appending
> `--service-account-file path/to/credentials.json` to every `pykmstool` command invocation in the further section.

> [!TIP]
> If you need to specify quota project to use, please append `--quota-project-id <...>`
> on every invocation of `pykmstool` commands listed in the further section.

### Tool usage

#### Generating a CSR

Generate and sign a CSR using a crypto key version specified by `--key-version-name` parameter.
The name specified in the `--x509-name` parameter must be compliant with the [RFC4514](https://datatracker.ietf.org/doc/html/rfc4514)
format and will be embedded within the resulting CSR.

```
python3 pykmstool.py sign-csr \
    --key-version-name projects/example-project/locations/europe-west6/keyRings/ExampleKeyRing/cryptoKeys/ExampleRSAKey1/cryptoKeyVersions/1 \
    --x509-name "C=US,O=Example Corp,CN=example.com"
```

Replace "US" with your two-letter country code, "Example Corp" with your organization name (company's name) and "example.com" with your company's domain.

See `--help` for all other available parameters.

> [!NOTE]
> Required GCP IAM permissions:
> ```
> cloudkms.cryptoKeyVersions.get
> cloudkms.cryptoKeyVersions.viewPublicKey
> cloudkms.cryptoKeyVersions.useToSign
> ```

> [!NOTE]
> IAM Condition to scope those permissions to a single key (optional):
> ```
> (
>   resource.type == "cloudkms.googleapis.com/CryptoKey" &&
>   resource.name == "projects/{projectName}/locations/{location}/keyRings/{keyRingName}/cryptoKeys/{keyName}"
> ) || (
>   resource.type == "cloudkms.googleapis.com/CryptoKeyVersion" &&
>   resource.name.startsWith("projects/{projectName}/locations/{location}/keyRings/{keyRingName}/cryptoKeys/{keyName}/cryptoKeyVersions/"
> )
> ```
> Substitute `{...}` placeholders with appropriate names.

> [!TIP]
> EV Code Signing Certificate Authorities would usually not be very strict about the X.509 Name embedded inside the Certificate Signing Request.
> If there were no special instructions about that provided by the CA, it should be fully sufficient to just set "C" (Country), "O" (Company name), "CN" (Company's domain) keys, just as in the example command provided above.

#### Getting a PEM public key for given key version

```
python3 pykmstool.py get-public-key \
    --key-version-name projects/example-project/locations/europe-west6/keyRings/ExampleKeyRing/cryptoKeys/ExampleRSAKey1/cryptoKeyVersions/1
```

> [!NOTE]
> Required GCP IAM permissions:
> ```
> cloudkms.cryptoKeyVersions.get
> cloudkms.cryptoKeyVersions.viewPublicKey
> ```

#### Listing all enabled key versions globally or for a given location/project ID:

Resources will be listed only if the account has sufficient permissions to list resources.

```
# Only search within a specified project and location ID
python3 pykmstool.py list-key-versions --project-id example-project --location-id europe-west6
# Search within a given location throughout all available projects
python3 pykmstool.py list-key-versions --location-id europe-west6
# Search within a project throughout all possible locations (slow)
python3 pykmstool.py list-key-versions --project-id example-project
# Search globally (slow)
python3 pykmstool.py list-key-versions
```

> [!NOTE]
> Required GCP IAM permissions (assuming that both `--location-id` and `--project-id` are provided):
> ```
> cloudkms.keyRings.list
> cloudkms.cryptoKeys.list	
> cloudkms.cryptoKeyVersions.list	
> ```

## Docker usage

> [!TIP]
> With the Docker flow, you don't need to perform "Installation" and "GCP Authentication" steps listed above. The Docker version will automatically lead you through those processes.

### Executing commands

```
docker run \
   -v ./gcloud-config:/root/.config/gcloud \
   -it ghcr.io/icedevml/pykmstool:v7 \
   -- \
   sign-csr \
   --key-version-name projects/example-project/locations/europe-west6/keyRings/ExampleKeyRing/cryptoKeys/ExampleRSAKey1/cryptoKeyVersions/1 \
   --x509-name "C=US,O=Example Corp,CN=example.com"
```

On the first run, this command will automatically lead you through the GCP sign in process.

See "Tool usage" section above for more information about supported commands.

### Revoking authentication

Remember to invalidate your credentials after finishing work with the tool, which could be done using:

```
docker run \
   -v ./gcloud-config:/root/.config/gcloud \
   -it ghcr.io/icedevml/pykmstool:v7 \
   docker-revoke-credentials
```
