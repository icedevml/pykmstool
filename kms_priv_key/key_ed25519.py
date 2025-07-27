"""
icedevml/pykmstool - Google Cloud KMS Certificate Signing Request (CSR) Generation Tool
BSD 3-Clause "New" License

This code portion was inspired by https://github.com/reaperhulk/vault-signing
Original license BSD-3-Clause (author: @reaperhulk)
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.utils import Buffer
from google.cloud.kms_v1 import KeyManagementServiceClient, CryptoKeyVersion

from kms_priv_key.base_key import BaseKMSPrivateKey


class KMSEd25519PrivateKey(ed25519.Ed25519PrivateKey, BaseKMSPrivateKey):
    def __init__(
            self,
            client: KeyManagementServiceClient,
            ckv: CryptoKeyVersion
    ):
        super().__init__(client, ckv, hash_algorithm=lambda: None)

    def __copy__(self) -> Ed25519PrivateKey:
        return KMSEd25519PrivateKey(
            client=self._client,
            ckv=self._ckv
        )

    def public_key(self) -> Ed25519PublicKey:
        return self._common_public_key()

    def sign(self, data: Buffer) -> bytes:
        return self._common_sign(data, algorithm=lambda: None)

    def private_bytes(self, encoding: serialization.Encoding, format: serialization.PrivateFormat,
                      encryption_algorithm: serialization.KeySerializationEncryption) -> bytes:
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")

    def private_bytes_raw(self) -> bytes:
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")
