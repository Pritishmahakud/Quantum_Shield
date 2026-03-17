from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def rsa_keygen():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key, private_key, len(pub_pem)


def rsa_encrypt(public_key, message: str) -> bytes:
    # RSA-OAEP can only encrypt small messages directly
    # For longer messages, chunk or use hybrid. Here we handle chunking.
    msg_bytes = message.encode('utf-8')
    max_chunk = 190  # safe for 2048-bit RSA with OAEP-SHA256
    chunks = [msg_bytes[i:i+max_chunk] for i in range(0, len(msg_bytes), max_chunk)]
    encrypted_chunks = []
    for chunk in chunks:
        enc = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(enc)
    # Join chunks with length prefix for decryption
    import struct
    result = struct.pack('>I', len(encrypted_chunks))
    for chunk in encrypted_chunks:
        result += struct.pack('>I', len(chunk)) + chunk
    return result


def rsa_decrypt(private_key, ciphertext: bytes) -> str:
    import struct
    offset = 0
    num_chunks = struct.unpack_from('>I', ciphertext, offset)[0]
    offset += 4
    decrypted = b''
    for _ in range(num_chunks):
        chunk_len = struct.unpack_from('>I', ciphertext, offset)[0]
        offset += 4
        chunk = ciphertext[offset:offset+chunk_len]
        offset += chunk_len
        decrypted += private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return decrypted.decode('utf-8')
