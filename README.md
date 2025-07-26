# Google Cloud KMS Certificate Signing Request (CSR) Generation Tool

## Usage

### Installation

1. Clone this repository.
2. Create a virtual environment and install required dependencies:
    ```
    python3 -m venv venv
    source venv/bin/activate
    pip3 install -r requirements.txt
    ```

### GCP Authentication

Create application default credentials:

```
gcloud auth application-default login
```

Or alternatively you can manually specify a service account JSON key file by appending
`--service-account-file path/to/credentials.json` to every command.

### Tool usage

Generating a CSR:

```
python3 pykmstool.py sign-csr && \
    --key-version-name projects/example-project/locations/europe-west6/keyRings/ExampleKeyRing/cryptoKeys/ExampleRSAKey1/cryptoKeyVersions/1 && \
    --x509-name "C=US,O=Example Corp,CN=example.com"
```

Getting a PEM public key for given key version:

```
python3 pykmstool.py get-public-key && \
    --key-version-name projects/example-project/locations/europe-west6/keyRings/ExampleKeyRing/cryptoKeys/ExampleRSAKey1/cryptoKeyVersions/1
```

Listing all enabled key versions for a given location and/or project ID (only if the account has sufficient permissions to list resources):

```
python3 pykmstool.py list-key-versions --project-id example-project --location-id europe-west6 
```

## Docker usage

```
docker run -v ./gcloud-config:/root/.config/gcloud -it ghcr.io/icedevml/pykmstool:v1 sign-csr <... arguments ...>
```

Remember to delete `./gcloud-config` directory after finishing work with the tool.
