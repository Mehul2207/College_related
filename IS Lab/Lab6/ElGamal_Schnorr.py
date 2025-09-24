from Crypto.Util.number import getPrime, inverse, bytes_to_long
from random import randint
from hashlib import sha256
from Crypto.Random import get_random_bytes
from math import gcd

# ----------------- ElGamal Key Generation -----------------
def generate_elgamal_keys(bits=256):
    p = getPrime(bits)           # prime
    g = randint(2, p - 1)        # generator
    x = randint(1, p - 2)        # private key
    y = pow(g, x, p)             # public key
    return (p, g, y), (p, g, x)

# ----------------- ElGamal Signing -----------------
def sign_elgamal(private_key, document):
    p, g, x = private_key
    while True:
        k = randint(1, p - 2)    # random k
        if gcd(k, p - 1) == 1:
            break
    h = int(sha256(document.encode()).hexdigest(), 16) % p  # hash
    r = pow(g, k, p)               # r = g^k mod p
    k_inv = inverse(k, p - 1)      
    s = (k_inv * (h - x * r)) % (p - 1)
    return (r, s)

# ----------------- ElGamal Verification -----------------
def verify_elgamal(public_key, document, signature):
    p, g, y = public_key
    r, s = signature
    h = int(sha256(document.encode()).hexdigest(), 16) % p
    left = pow(y, r, p) * pow(r, s, p) % p
    right = pow(g, h, p)
    return left == right

# ----------------- Schnorr Key Generation -----------------
def generate_schnorr_keypair(p, g, q):
    x = bytes_to_long(get_random_bytes(32)) % (p-1)  # private key
    y = pow(g, x, p)                                  # public key
    return x, y

# ----------------- Schnorr Signing -----------------
def schnorr_sign(document, private_key, p, g, q):
    x = private_key
    k = bytes_to_long(get_random_bytes(32)) % q
    r = pow(g, k, p)
    e = int(sha256((str(r) + document).encode()).hexdigest(), 16) % q
    s = (k - x * e) % (p-1)
    return r, s

# ----------------- Schnorr Verification -----------------
def schnorr_verify(document, signature, public_key, p, g, q):
    r, s = signature
    e = int(sha256((str(r) + document).encode()).hexdigest(), 16) % q
    left = (pow(g, s, p) * pow(public_key, e, p)) % p
    right = r % p
    return left == right

# ----------------- Test ElGamal -----------------
document = "Elgamal protected document"
public_key, private_key = generate_elgamal_keys()
signature = sign_elgamal(private_key, document)
print(f"ElGamal Signature: {signature}")
print(f"ElGamal Signature valid: {verify_elgamal(public_key, document, signature)}")

# ----------------- Test Schnorr -----------------
p = getPrime(256)
q = getPrime(128)
g = 2
schnorr_private_key, schnorr_public_key = generate_schnorr_keypair(p, g, q)
document = "Schnorr protected document"
schnorr_signature = schnorr_sign(document, schnorr_private_key, p, g, q)
print("Schnorr Signature:", schnorr_signature)
print("Schnorr Signature valid:", schnorr_verify(document, schnorr_signature, schnorr_public_key, p, g, q))
