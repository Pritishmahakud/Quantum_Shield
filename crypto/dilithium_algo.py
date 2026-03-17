"""
CRYSTALS-Dilithium — Post-Quantum Digital Signatures
Based on Module Learning With Errors (Module-LWE) lattice hardness.
NIST Standard: ML-DSA (FIPS 204, 2024)
"""
from dilithium_py.ml_dsa import ML_DSA_44
import time


def dilithium_keygen():
    """Generate Dilithium-2 public/private key pair."""
    pk, sk = ML_DSA_44.keygen()
    return pk, sk


def dilithium_sign(sk: bytes, message: str) -> bytes:
    """Sign a message using the private key."""
    msg_bytes = message.encode('utf-8')
    signature = ML_DSA_44.sign(sk, msg_bytes)
    return signature


def dilithium_verify(pk: bytes, message: str, signature: bytes) -> bool:
    """Verify a signature using the public key. Returns True if valid."""
    msg_bytes = message.encode('utf-8')
    try:
        result = ML_DSA_44.verify(pk, msg_bytes, signature)
        return result
    except Exception:
        return False


def dilithium_full_demo(message: str) -> dict:
    """Run a full sign + verify cycle and return results."""
    t0 = time.perf_counter()

    pk, sk = dilithium_keygen()
    sig    = dilithium_sign(sk, message)
    valid  = dilithium_verify(pk, message, sig)

    ms = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "public_key_hex":  pk.hex()[:64] + "…",
        "public_key_size": len(pk),
        "secret_key_size": len(sk),
        "signature_hex":   sig.hex()[:64] + "…",
        "signature_size":  len(sig),
        "verified":        valid,
        "time_ms":         ms,
        "algorithm":       "CRYSTALS-Dilithium-2",
        "nist_standard":   "ML-DSA (FIPS 204, 2024)",
        "basis":           "Module Learning With Errors (Module-LWE)",
        "quantum_safe":    True,
    }


def dilithium_verify_tampered(pk: bytes, original_msg: str, tampered_msg: str, signature: bytes) -> dict:
    """Show that tampering with the message breaks verification."""
    original_valid = dilithium_verify(pk, original_msg, signature)
    tampered_valid = dilithium_verify(pk, tampered_msg, signature)
    return {
        "original_valid": original_valid,
        "tampered_valid": tampered_valid,
    }
