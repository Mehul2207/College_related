from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os

# Key generation
private_key = ec.generate_private_key(ec.SECP256R1())   # our private key
public_key = private_key.public_key()                  # our public key

# Export public key (PEM format)
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("Public Key (PEM):")
print(pem_public_key.decode())

# Simulate other party's keys
other_private_key = ec.generate_private_key(ec.SECP256R1())
other_public_key = other_private_key.public_key()

# Shared secret via ECDH
shared_secret = other_private_key.exchange(ec.ECDH(), public_key)

# Derive AES key from shared secret (SHA-256)
aes_key = hashes.Hash(hashes.SHA256())
aes_key.update(shared_secret)
aes_key = aes_key.finalize()[:32]

# Message to encrypt
message = b"Secure Transactions"

# AES-GCM encryption
nonce = os.urandom(12)  # random nonce
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()
tag = encryptor.tag

print("Ciphertext:", ciphertext.hex())
print("Nonce:", nonce.hex())
print("Tag:", tag.hex())

# AES-GCM decryption
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
decryptor = cipher.decryptor()
decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

print("Decrypted message:", decrypted_message.decode())
