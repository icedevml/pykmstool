"""
icedevml/pykmstool - Google Cloud KMS Certificate Signing Request (CSR) Generation Tool
BSD 3-Clause "New" License

This code portion was inspired by https://github.com/reaperhulk/vault-signing
Original license BSD-3-Clause (author: @reaperhulk)
"""

import typing

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    utils as asym_utils,
)
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from google.cloud.kms_v1 import KeyManagementServiceClient, CryptoKeyVersion

from kms_priv_key.base_key import BaseKMSPrivateKey, KMSHashAlgorithm


class KMSRSAPrivateKey(rsa.RSAPrivateKey, BaseKMSPrivateKey):
    def __init__(self, client: KeyManagementServiceClient, ckv: CryptoKeyVersion, hash_algorithm: KMSHashAlgorithm):
        super().__init__(client, ckv, hash_algorithm)

    def __copy__(self) -> RSAPrivateKey:
        return KMSRSAPrivateKey(
            client=self._client,
            ckv=self._ckv,
            hash_algorithm=self._hash_algorithm
        )

    def public_key(self) -> RSAPublicKey:
        return self._common_public_key()

    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> bytes:
        if not isinstance(padding, PKCS1v15):
            raise RuntimeError("Unsupported padding type requested.")

        return self._common_sign(data, algorithm)

    def key_size(self) -> int:
        return self.public_key().key_size

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError("Only asymmetric signing is supported in this implementation.")

    def private_numbers(self) -> "rsa.RSAPrivateNumbers":
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")
