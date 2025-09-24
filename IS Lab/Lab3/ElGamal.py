from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random

# Key generation
p = getPrime(256)              # large prime
g = random.randint(2, p-1)     # generator
x = random.randint(1, p-2)     # private key
h = pow(g, x, p)               # public key component

print("p (prime):", p)
print("g (generator):", g)
print("h (public key):", h)
print("x (private key):", x)

# Encryption
message = b"Confidential Data"
k = random.randint(1, p-2)     # random session key
c1 = pow(g, k, p)              # first ciphertext part
m = bytes_to_long(message)     # plaintext → int
c2 = (m * pow(h, k, p)) % p    # second ciphertext part

print("c1:", c1)
print("c2:", c2)

# Decryption
s = pow(c1, x, p)              # shared secret
s_inv = inverse(s, p)          # inverse of secret
m_decrypted = (c2 * s_inv) % p # recover plaintext
decrypted_message = long_to_bytes(m_decrypted)

print("Decrypted message:", decrypted_message.decode())
