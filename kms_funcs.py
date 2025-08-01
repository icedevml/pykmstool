"""
icedevml/pykmstool - Google Cloud KMS Certificate Signing Request (CSR) Generation Tool
BSD 3-Clause "New" License
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_pem_x509_csr
from google.cloud import kms

from kms_priv_key import create_pyca_private_key


def kms_get_public_key(*, client: kms.KeyManagementServiceClient, key_version_name: str) -> str:
    signer_priv_key = create_pyca_private_key(client, key_version_name)
    return signer_priv_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode('ascii')


def kms_sign_csr(*, client: kms.KeyManagementServiceClient, key_version_name: str, rfc4514_name: str) -> str:
    signer_priv_key = create_pyca_private_key(client, key_version_name)

    name = x509.Name.from_rfc4514_string(rfc4514_name)

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
    )

    cert = builder.sign(signer_priv_key, signer_priv_key.hash_algorithm())
    return cert.public_bytes(serialization.Encoding.PEM).decode('ascii')


def kms_verify_csr(
        *,
        client: kms.KeyManagementServiceClient,
        key_version_name: str,
        csr_pem: str,
        expected_rfc4514_name: str
):
    signer_priv_key = create_pyca_private_key(client, key_version_name)

    csr = load_pem_x509_csr(csr_pem.encode('ascii'))

    if csr.subject != x509.Name.from_rfc4514_string(expected_rfc4514_name):
        raise RuntimeError("Mismatched RFC4514 name.")

    if not csr.is_signature_valid:
        raise RuntimeError("Produced CSR doesn\'t have valid signature.")

    if csr.public_key() != signer_priv_key.public_key():
        raise RuntimeError("Mismatched public keys in CSR and KMS.")
