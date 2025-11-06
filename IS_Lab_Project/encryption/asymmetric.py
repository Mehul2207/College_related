import random
import math

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17]:
        if n % p == 0:
            return n == p
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(min_value, max_value):
    """Generate a prime number within range."""
    prime = random.randrange(min_value, max_value)
    while not is_prime(prime):
        prime = random.randrange(min_value, max_value)
    return prime

def mod_inverse(e, phi):
    """Extended Euclidean Algorithm to find modular multiplicative inverse."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, d, _ = extended_gcd(e, phi)
    return d % phi

# RSA
def rsa_generate_keys():
    p = generate_prime(100, 1000)
    q = generate_prime(100, 1000)
    while p == q:
        q = generate_prime(100, 1000)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common public exponent
    while math.gcd(e, phi) != 1:
        e = random.randrange(3, phi)
    d = mod_inverse(e, phi)
    public_key = (e, n)
    private_key = (d, n)
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    plaintext_int = int.from_bytes(plaintext.encode(), 'big')
    if plaintext_int >= n:
        raise ValueError("Plaintext too large for n")
    ciphertext = pow(plaintext_int, e, n)
    return str(ciphertext)

def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    ciphertext_int = int(ciphertext)
    plaintext_int = pow(ciphertext_int, d, n)
    return plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')

# Rabin Cryptosystem
def rabin_generate_keys():
    p = generate_prime(100, 1000)
    while p % 4 != 3:
        p = generate_prime(100, 1000)
    q = generate_prime(100, 1000)
    while q % 4 != 3 or q == p:
        q = generate_prime(100, 1000)
    n = p * q
    public_key = n
    private_key = (p, q)
    return private_key, public_key

def rabin_encrypt(plaintext, public_key):
    n = public_key
    plaintext_int = int.from_bytes(plaintext.encode(), 'big')
    if plaintext_int >= n:
        raise ValueError("Plaintext too large for n")
    ciphertext = pow(plaintext_int, 2, n)
    return str(ciphertext)

def rabin_decrypt(ciphertext, private_key):
    p, q = private_key
    n = p * q
    c = int(ciphertext)
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    # Simplified: Assuming one valid root (actual Rabin needs all four roots)
    yp, yq = mp, mq
    if yp > p // 2:
        yp = p - yp
    if yq > q // 2:
        yq = q - yq
    _, x, _ = extended_gcd(p, q)
    r = (yp + x * (yq - yp) * p) % n
    return r.to_bytes((r.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')

# ElGamal
def elgamal_generate_keys():
    p = generate_prime(100, 1000)
    g = random.randrange(2, p)
    x = random.randrange(1, p - 1)
    y = pow(g, x, p)
    public_key = (p, g, y)
    private_key = (p, g, x)
    return private_key, public_key

def elgamal_encrypt(plaintext, public_key):
    p, g, y = public_key
    k = random.randrange(1, p - 1)
    plaintext_int = int.from_bytes(plaintext.encode(), 'big')
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (plaintext_int * s) % p
    return (c1, c2)

def elgamal_decrypt(ciphertext, private_key):
    p, g, x = private_key
    c1, c2 = ciphertext
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    plaintext_int = (c2 * s_inv) % p
    return plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')

def extended_gcd(a, b):
    """Helper for modular inverse."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y