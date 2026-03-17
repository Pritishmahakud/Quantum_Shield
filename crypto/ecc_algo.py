from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def ecc_keygen():
    alice_priv = generate_private_key(SECP256R1())
    alice_pub  = alice_priv.public_key()
    bob_priv   = generate_private_key(SECP256R1())
    bob_pub    = bob_priv.public_key()

    alice_pub_hex = alice_pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint
    ).hex()

    return alice_pub, alice_priv, bob_pub, bob_priv, alice_pub_hex


def _derive_aes_key(private_key, peer_public_key: EllipticCurvePublicKey) -> bytes:
    shared_secret = private_key.exchange(ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh-aes-key'
    ).derive(shared_secret)


def ecc_encrypt(alice_priv, bob_pub, message: str):
    key = _derive_aes_key(alice_priv, bob_pub)
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(iv, message.encode('utf-8'), None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, iv, tag


def ecc_decrypt(bob_priv, alice_pub, ciphertext: bytes, iv: bytes, tag: bytes) -> str:
    key = _derive_aes_key(bob_priv, alice_pub)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + tag, None).decode('utf-8')
