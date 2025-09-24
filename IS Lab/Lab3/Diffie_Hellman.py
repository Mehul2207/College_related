from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
import time

# Generate DSA parameters (p, q, g)
key = DSA.generate(2048)
p = key.p
g = key.g

# ----------------- Peer 1 key generation -----------------
start_time = time.perf_counter()
private_key_1 = int.from_bytes(get_random_bytes(32), byteorder='big') % p
public_key_1 = pow(g, private_key_1, p)
key_gen_time_1 = time.perf_counter() - start_time

# ----------------- Peer 2 key generation -----------------
start_time = time.perf_counter()
private_key_2 = int.from_bytes(get_random_bytes(32), byteorder='big') % p
public_key_2 = pow(g, private_key_2, p)
key_gen_time_2 = time.perf_counter() - start_time

# ----------------- Shared secret computation -----------------
start_time = time.perf_counter()
shared_secret_1 = pow(public_key_2, private_key_1, p)  # Peer 1 computes secret
key_exchange_time_1 = time.perf_counter() - start_time

start_time = time.perf_counter()
shared_secret_2 = pow(public_key_1, private_key_2, p)  # Peer 2 computes secret
key_exchange_time_2 = time.perf_counter() - start_time

# ----------------- Print timings -----------------
print(f"Key Generation Time (Peer 1): {key_gen_time_1:.10f} seconds")
print(f"Key Generation Time (Peer 2): {key_gen_time_2:.10f} seconds")
print(f"Key Exchange Time (Peer 1): {key_exchange_time_1:.10f} seconds")
print(f"Key Exchange Time (Peer 2): {key_exchange_time_2:.10f} seconds")
