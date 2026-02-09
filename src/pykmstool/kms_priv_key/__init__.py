"""
icedevml/pykmstool - Google Cloud KMS Certificate Signing Request (CSR) Generation Tool
BSD 3-Clause "New" License
"""

import typing

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from google.cloud.kms_v1 import KeyManagementServiceClient, CryptoKeyVersion

from pykmstool.kms_priv_key.base_key import KMSHashAlgorithm
from pykmstool.kms_priv_key.key_ec import KMSECPrivateKey
from pykmstool.kms_priv_key.key_ed25519 import KMSEd25519PrivateKey
from pykmstool.kms_priv_key.key_rsa import KMSRSAPrivateKey


type KMSPrivateKey = KMSRSAPrivateKey | KMSECPrivateKey | KMSEd25519PrivateKey

def build_kms_priv_key(
        cls: typing.Type[KMSPrivateKey],
        hash_algorithm: KMSHashAlgorithm = None,
        curve: typing.Type[EllipticCurve] = None,
) -> typing.Callable[..., KMSPrivateKey]:
    bind_kwargs = {}

    if hash_algorithm:
        bind_kwargs.update({"hash_algorithm": hash_algorithm})

    if curve:
        bind_kwargs.update({"curve": curve})

    return lambda *args, **kwargs: cls(*args, **kwargs, **bind_kwargs)


def create_pyca_private_key(client: KeyManagementServiceClient, key_version_name: str)\
        -> KMSPrivateKey:
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
