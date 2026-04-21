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
from cryptography.hazmat.primitives.asymmetric.padding import PSS, PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from google.cloud.kms_v1 import KeyManagementServiceClient, CryptoKeyVersion


def crc32c(data: bytes) -> int:
    import crcmod  # type: ignore

    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
    return crc32c_fun(data)


class BaseKMSPrivateKey:
    def __init__(
            self,
            client: KeyManagementServiceClient,
            ckv: CryptoKeyVersion,
            hash_algorithm: typing.Type[SHA256 | SHA384 | SHA512] | typing.Callable[[], None],
            rsa_padding: typing.Callable[[SHA256 | SHA384 | SHA512 | None], PKCS1v15 | PSS | None],
    ):
        self._client = client
        self._ckv = ckv
        self._hash_algorithm = hash_algorithm
        self._rsa_padding = rsa_padding

    @property
    def crypto_key_version(self):
        return self._ckv

    @property
    def hash_algorithm(self) -> typing.Type[SHA256 | SHA384 | SHA512] | typing.Callable[[], None]:
        return self._hash_algorithm

    @property
    def rsa_padding(self) -> typing.Callable[[SHA256 | SHA384 | SHA512 | None], PKCS1v15 | PSS | None]:
        return self._rsa_padding

    def _common_public_key(self):
        public_key = self._client.get_public_key(name=self._ckv.name)

        if not public_key.pem:
            raise RuntimeError("Unexpected public key format received from KMS.")

        return load_pem_public_key(public_key.pem.encode("ascii"))

    def _common_sign(self, data: utils.Buffer, algorithm: hashes.HashAlgorithm | None = None) -> bytes:
        instance_hash_obj = self.hash_algorithm()

        if not instance_hash_obj:
            if algorithm:
                raise RuntimeError("Unexpected algorithm parameter provided.")

            sign_response = self._client.asymmetric_sign(
                request={
                    "name": self._ckv.name,
                    "data": base64.b64encode(data).decode('ascii'),
                    "data_crc32c": crc32c(bytes(data)),
                }
            )
        else:
            if algorithm and algorithm.name != instance_hash_obj.name:
                raise RuntimeError("Requested incompatible hash algorithm.")

            h = hashes.Hash(instance_hash_obj)
            h.update(data)
            digest = h.finalize()

            sign_response = self._client.asymmetric_sign(
                request={
                    "name": self._ckv.name,
                    "digest": {instance_hash_obj.name: base64.b64encode(digest).decode('ascii')},
                    "digest_crc32c": crc32c(digest),
                }
            )

        if crc32c(sign_response.signature) != sign_response.signature_crc32c:
            raise RuntimeError("Mismatched CRC32C in the signature returned from KMS.")

        return sign_response.signature
