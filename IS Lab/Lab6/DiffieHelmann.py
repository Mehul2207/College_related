from Crypto.Util.number import getPrime
from random import randint

# ----------------- Generate DH key pair -----------------
def generate_dh_keypair(p, g):
    # private key: random integer 1 <= private_key <= p-2
    private_key = randint(1, p - 2)
    # public key: g^private_key mod p
    public_key = pow(g, private_key, p)
    return private_key, public_key

# ----------------- "Sign" by raising other's public key to own private key -----------------
def sign(private_key, other_public_key, p):
    return pow(other_public_key, private_key, p)

# ----------------- Verify signature by recomputing -----------------
def verify(private_key, other_public_key, shared_secret, p):
    return sign(private_key, other_public_key, p) == shared_secret

# ----------------- Parameters -----------------
p = getPrime(256)  # large prime for DH
g = 2              # generator

# ----------------- Key generation -----------------
private_key_A, public_key_A = generate_dh_keypair(p, g)
private_key_B, public_key_B = generate_dh_keypair(p, g)

# ----------------- Compute shared secret -----------------
shared_secret = sign(private_key_A, public_key_B, p)

# ----------------- Verify that B can compute same secret -----------------
print("Diffie-Hellman Signature valid:", verify(private_key_B, public_key_A, shared_secret, p))
print("Shared secret:", shared_secret)
