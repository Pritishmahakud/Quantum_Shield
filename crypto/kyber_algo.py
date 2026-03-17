from kyber_py.ml_kem import ML_KEM_512
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib, os


def kyber_keygen():
    # pk, sk = ML_KEM_512.keygen()
    pk, sk = ML_KEM_512.keygen()
    return pk, sk


def kyber_encaps(pk: bytes):
    # ct_kem, raw_shared = Kyber512.enc(pk)
    raw_kem, ct_shared = ML_KEM_512.encaps(pk)
    # aes_key = hashlib.sha256(raw_shared).digest()
    aes_key = hashlib.sha256(raw_kem).digest()
    # return ct_kem, aes_key
    return ct_shared, aes_key


def kyber_decaps(sk: bytes, ct_kem: bytes) -> bytes:
    raw_shared = ML_KEM_512.decaps(sk, ct_kem)
    return hashlib.sha256(raw_shared).digest()


def kyber_encrypt(aes_key: bytes, message: str):
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(iv, message.encode('utf-8'), None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, iv, tag


def kyber_decrypt(aes_key: bytes, ciphertext: bytes, iv: bytes, tag: bytes) -> str:
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ciphertext + tag, None).decode('utf-8')
