"""
icedevml/pykmstool - Google Cloud KMS Certificate Signing Request (CSR) Generation Tool
BSD 3-Clause "New" License

This code portion was inspired by https://github.com/reaperhulk/vault-signing
Original license BSD-3-Clause (author: @reaperhulk)
"""

import typing

from cryptography import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurveSignatureAlgorithm, EllipticCurve, ECDH, \
    EllipticCurvePublicKey, EllipticCurvePrivateKey, EllipticCurvePrivateNumbers
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from google.cloud.kms_v1 import KeyManagementServiceClient, CryptoKeyVersion

from pykmstool.kms_priv_key.base_key import BaseKMSPrivateKey


class KMSECPrivateKey(ec.EllipticCurvePrivateKey, BaseKMSPrivateKey):
    def __init__(
            self,
            client: KeyManagementServiceClient,
            ckv: CryptoKeyVersion,
            hash_algorithm: typing.Type[SHA256 | SHA384 | SHA512],
            curve: typing.Type[ec.EllipticCurve]
    ):
        super().__init__(client, ckv, hash_algorithm)
        self._curve = curve

    def __copy__(self) -> EllipticCurvePrivateKey:
        return KMSECPrivateKey(
            client=self._client,
            ckv=self._ckv,
            hash_algorithm=self._hash_algorithm,
            curve=self._curve
        )

    def public_key(self) -> EllipticCurvePublicKey:
        return self._common_public_key()

    def sign(self, data: utils.Buffer, signature_algorithm: EllipticCurveSignatureAlgorithm) -> bytes:
        return self._common_sign(data, signature_algorithm.algorithm)

    @property
    def hash_algorithm(self) -> typing.Type[SHA256 | SHA384 | SHA512]:
        return self._hash_algorithm

    @property
    def curve(self) -> EllipticCurve:
        return self._curve()

    @property
    def key_size(self) -> int:
        return self.curve.key_size

    def exchange(self, algorithm: ECDH, peer_public_key: EllipticCurvePublicKey) -> bytes:
        raise NotImplementedError("Key exchange is not supported in this implementation.")

    def private_numbers(self) -> EllipticCurvePrivateNumbers:
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")

    def private_bytes(self, encoding: serialization.Encoding, format: serialization.PrivateFormat,
                      encryption_algorithm: serialization.KeySerializationEncryption) -> bytes:
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")
