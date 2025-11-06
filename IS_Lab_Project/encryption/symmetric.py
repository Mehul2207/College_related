from Cryptodome.Cipher import DES, AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

# Utility function used by avalanche test logic in app.py
def bytes_xor(a, b):
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))

def count_bit_difference(bytes1, bytes2):
    """Counts the total number of differing bits between two byte strings."""
    min_len = min(len(bytes1), len(bytes2))
    bytes1 = bytes1[:min_len]
    bytes2 = bytes2[:min_len]

    diff_bytes = bytes_xor(bytes1, bytes2)
    bit_difference = 0
    for byte in diff_bytes:
        # Counts the number of '1's in the binary representation (popcount)
        # bin(byte) converts to '0b...', count('1') ignores the prefix
        bit_difference += bin(byte).count('1')
    return bit_difference

def des_encrypt_bytes(plain_bytes, key):
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    # Using secrets for IV, which is prefixed to the ciphertext
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plain_bytes, DES.block_size))
    return iv + ct

def des_decrypt_bytes(enc_bytes, key):
    iv = enc_bytes[:8]
    ct = enc_bytes[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size)

def aes_encrypt_bytes(plain_bytes, key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes")
    # Using secrets for IV, which is prefixed to the ciphertext
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plain_bytes, AES.block_size))
    return iv + ct

def aes_decrypt_bytes(enc_bytes, key):
    iv = enc_bytes[:16]
    ct = enc_bytes[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)