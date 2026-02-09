"""
icedevml/pykmstool - Google Cloud KMS Certificate Signing Request (CSR) Generation Tool
BSD 3-Clause "New" License

This code portion was inspired by https://github.com/reaperhulk/vault-signing
Original license BSD-3-Clause (author: @reaperhulk)
"""

import base64
import typing

from cryptography import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    utils as asym_utils,
)
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from google.cloud.kms_v1 import KeyManagementServiceClient, CryptoKeyVersion

type KMSHashAlgorithm = typing.Type[SHA256 | SHA384 | SHA512]

def crc32c(data: bytes) -> int:
    import crcmod  # type: ignore

    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
    return crc32c_fun(data)


class BaseKMSPrivateKey:
    def __init__(
            self,
            client: KeyManagementServiceClient,
            ckv: CryptoKeyVersion,
            hash_algorithm: KMSHashAlgorithm | typing.Callable[[], None]
    ):
        self._client = client
        self._ckv = ckv
        self._hash_algorithm = hash_algorithm

    @property
    def crypto_key_version(self):
        return self._ckv

    @property
    def hash_algorithm(self) -> KMSHashAlgorithm:
        return self._hash_algorithm

    def _common_public_key(self):
        public_key = self._client.get_public_key(name=self._ckv.name)

        if not public_key.pem:
            raise RuntimeError("Unexpected public key format received from KMS.")

        return load_pem_public_key(public_key.pem.encode("ascii"))

    def _common_sign(self, data: utils.Buffer, algorithm: hashes.HashAlgorithm | typing.Callable[[], None]) -> bytes:
        if isinstance(algorithm, asym_utils.Prehashed):
            raise RuntimeError("Prehashed data is not supported.")

        if not self.hash_algorithm():
            if algorithm():
                raise RuntimeError("Unexpected algorithm parameter provided.")

            sign_response = self._client.asymmetric_sign(
                request={
                    "name": self._ckv.name,
                    "data": base64.b64encode(data).decode('ascii'),
                    "data_crc32c": crc32c(data),
                }
            )
        else:
            if algorithm.name != self.hash_algorithm.name:
               raise RuntimeError("Requested incompatible hash algorithm.")

            h = hashes.Hash(self.hash_algorithm())
            h.update(data)
            digest = h.finalize()

            sign_response = self._client.asymmetric_sign(
                request={
                    "name": self._ckv.name,
                    "digest": {self.hash_algorithm.name: base64.b64encode(digest).decode('ascii')},
                    "digest_crc32c": crc32c(digest),
                }
            )

        if crc32c(sign_response.signature) != sign_response.signature_crc32c:
            raise RuntimeError("Mismatched CRC32C in the signature returned from KMS.")

        return sign_response.signature

