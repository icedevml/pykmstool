"""
Modified from https://github.com/reaperhulk/vault-signing
Original license BSD-3-Clause (author: @reaperhulk)
"""

import base64
import typing

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    utils as asym_utils,
)
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from google.cloud.kms_v1 import KeyManagementServiceClient, GetPublicKeyRequest, PublicKey


def crc32c(data: bytes) -> int:
    """
    Calculates the CRC32C checksum of the provided data.
    Args:
        data: the bytes over which the checksum should be calculated.
    Returns:
        An int representing the CRC32C checksum of the provided bytes.
    """
    import crcmod  # type: ignore

    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
    return crc32c_fun(data)


class GoogleCloudKMSRSAPrivateKey(rsa.RSAPrivateKey):
    def __init__(self, client: KeyManagementServiceClient, key_version_name: str):
        self.client = client
        self.key_version_name = key_version_name

    def __copy__(self) -> RSAPrivateKey:
        raise NotImplementedError()

    def _key_info(self):
        # Get key info from OCI Vault
        pass

    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> bytes:
        assert not isinstance(algorithm, asym_utils.Prehashed)
        assert isinstance(padding, PKCS1v15)

        h = hashes.Hash(algorithm)
        h.update(data)
        digest = h.finalize()

        digest_b64 = base64.b64encode(digest).decode('ascii')

        if isinstance(algorithm, hashes.SHA256):
            digest_obj = {"sha256": digest_b64}
        elif isinstance(algorithm, hashes.SHA384):
            digest_obj = {"sha384": digest_b64}
        elif isinstance(algorithm, hashes.SHA512):
            digest_obj = {"sha512": digest_b64}
        else:
            raise RuntimeError("Unsupported algorithm: " + repr(algorithm))

        digest_crc32c = crc32c(digest)

        sign_response = self.client.asymmetric_sign(
            request={
                "name": self.key_version_name,
                "digest": digest_obj,
                "digest_crc32c": digest_crc32c,
            }
        )

        if crc32c(sign_response.signature) != sign_response.signature_crc32c:
            raise RuntimeError("Mismatched CRC32C in the signature returned from KMS.")

        return sign_response.signature

    # Every method below here is unimplemented for now but needs to be
    # present to satisfy the interface.
    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError()

    def key_size(self) -> int:
        raise NotImplementedError()

    def public_key(self) -> "rsa.RSAPublicKey":
        public_key = self.client.get_public_key(name=self.key_version_name)

        if not public_key.pem:
            raise RuntimeError("Unexpected public key format received from KMS.")

        return load_pem_public_key(public_key.pem.encode("ascii"))

    def private_numbers(self) -> "rsa.RSAPrivateNumbers":
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()
