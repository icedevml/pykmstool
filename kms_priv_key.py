"""
Modified from https://github.com/reaperhulk/vault-signing
Original license BSD-3-Clause (author: @reaperhulk)
"""

import base64
import typing

from cryptography import utils
from cryptography.hazmat.primitives import serialization, hashes, _serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ec,
    ed25519,
    utils as asym_utils,
)
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurveSignatureAlgorithm, EllipticCurve, ECDH, \
    EllipticCurvePublicKey, EllipticCurvePrivateKey, EllipticCurvePrivateNumbers
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.utils import Buffer
from google.cloud.kms_v1 import KeyManagementServiceClient, CryptoKeyVersion

type HashAlgorithm = typing.Type[SHA256 | SHA384 | SHA512]

def crc32c(data: bytes) -> int:
    import crcmod  # type: ignore

    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
    return crc32c_fun(data)


class BaseKMSPrivateKey:
    def __init__(
            self,
            client: KeyManagementServiceClient,
            ckv: CryptoKeyVersion,
            hash_algorithm: HashAlgorithm | typing.Callable[[], None]
    ):
        self._client = client
        self._ckv = ckv
        self._hash_algorithm = hash_algorithm

    @property
    def crypto_key_version(self):
        return self._ckv

    @property
    def hash_algorithm(self) -> HashAlgorithm:
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


class KMSRSAPrivateKey(rsa.RSAPrivateKey, BaseKMSPrivateKey):
    def __init__(self, client: KeyManagementServiceClient, ckv: CryptoKeyVersion, hash_algorithm: HashAlgorithm):
        super().__init__(client, ckv, hash_algorithm)

    def __copy__(self) -> RSAPrivateKey:
        raise NotImplementedError()

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

    # Every method below here is unimplemented for now but needs to be
    # present to satisfy the interface.
    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError()

    def key_size(self) -> int:
        raise NotImplementedError()

    def private_numbers(self) -> "rsa.RSAPrivateNumbers":
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()


class KMSECPrivateKey(ec.EllipticCurvePrivateKey, BaseKMSPrivateKey):
    def __init__(
            self,
            client: KeyManagementServiceClient,
            ckv: CryptoKeyVersion,
            hash_algorithm: HashAlgorithm,
            curve: typing.Type[ec.EllipticCurve]
    ):
        super().__init__(client, ckv, hash_algorithm)
        self._curve = curve

    def __copy__(self) -> EllipticCurvePrivateKey:
        raise NotImplementedError()

    def public_key(self) -> EllipticCurvePublicKey:
        return self._common_public_key()

    def sign(self, data: utils.Buffer, signature_algorithm: EllipticCurveSignatureAlgorithm) -> bytes:
        return self._common_sign(data, signature_algorithm.algorithm)

    @property
    def hash_algorithm(self) -> HashAlgorithm:
        return self._hash_algorithm

    @property
    def curve(self) -> EllipticCurve:
        return self._curve()

    @property
    def key_size(self) -> int:
        return self.curve.key_size

    def exchange(self, algorithm: ECDH, peer_public_key: EllipticCurvePublicKey) -> bytes:
        raise NotImplementedError()

    def private_numbers(self) -> EllipticCurvePrivateNumbers:
        raise NotImplementedError()

    def private_bytes(self, encoding: _serialization.Encoding, format: _serialization.PrivateFormat,
                      encryption_algorithm: _serialization.KeySerializationEncryption) -> bytes:
        raise NotImplementedError()


class KMSEd25519PrivateKey(ed25519.Ed25519PrivateKey, BaseKMSPrivateKey):
    def __init__(
            self,
            client: KeyManagementServiceClient,
            ckv: CryptoKeyVersion
    ):
        super().__init__(client, ckv, hash_algorithm=lambda: None)

    def __copy__(self) -> Ed25519PrivateKey:
        pass

    def public_key(self) -> Ed25519PublicKey:
        return self._common_public_key()

    def sign(self, data: Buffer) -> bytes:
        return self._common_sign(data, algorithm=lambda: None)

    def private_bytes(self, encoding: _serialization.Encoding, format: _serialization.PrivateFormat,
                      encryption_algorithm: _serialization.KeySerializationEncryption) -> bytes:
        pass

    def private_bytes_raw(self) -> bytes:
        pass


def build_kms_priv_key(
        cls: typing.Type[KMSRSAPrivateKey | KMSECPrivateKey | KMSEd25519PrivateKey],
        hash_algorithm: HashAlgorithm = None,
        curve: typing.Type[EllipticCurve] = None,
) -> typing.Callable[..., KMSRSAPrivateKey | KMSECPrivateKey | KMSEd25519PrivateKey]:
    bind_kwargs = {}

    if hash_algorithm:
        bind_kwargs.update({"hash_algorithm": hash_algorithm})

    if curve:
        bind_kwargs.update({"curve": curve})

    return lambda *args, **kwargs: cls(*args, **kwargs, **bind_kwargs)


def create_pyca_private_key(client: KeyManagementServiceClient, key_version_name: str)\
        -> KMSRSAPrivateKey | KMSECPrivateKey | KMSEd25519PrivateKey:
    kms_alg_to_class = {
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256.name:
            build_kms_priv_key(KMSRSAPrivateKey, hash_algorithm=SHA256),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256.name:
            build_kms_priv_key(KMSRSAPrivateKey, hash_algorithm=SHA256),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256.name:
            build_kms_priv_key(KMSRSAPrivateKey, hash_algorithm=SHA256),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512.name:
            build_kms_priv_key(KMSRSAPrivateKey, hash_algorithm=SHA512),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256.name:
            build_kms_priv_key(KMSECPrivateKey, hash_algorithm=SHA256, curve=ec.SECP256R1),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384.name:
            build_kms_priv_key(KMSECPrivateKey, hash_algorithm=SHA384, curve=ec.SECP384R1),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256.name:
            build_kms_priv_key(KMSECPrivateKey, hash_algorithm=SHA256, curve=ec.SECP256K1),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519.name:
            build_kms_priv_key(KMSEd25519PrivateKey)
    }

    ckv = client.get_crypto_key_version(name=key_version_name)

    if ckv.algorithm.name not in kms_alg_to_class:
        raise ValueError("Unsupported KMS algorithm: " + ckv.algorithm.name)

    return kms_alg_to_class[ckv.algorithm.name](client, ckv)
