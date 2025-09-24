import hashlib
import random
import string
import time

# ----------------- Generate random dataset -----------------
def generate_random_strings(num_strings=50, min_len=5, max_len=20):
    dataset = []
    for _ in range(num_strings):
        length = random.randint(min_len, max_len)
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(s)
    return dataset

# ----------------- Hashing and timing -----------------
def compute_hashes(dataset, hash_func):
    hashes = []
    start_time = time.perf_counter()
    for item in dataset:
        h = hash_func(item.encode()).hexdigest()
        hashes.append(h)
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return hashes, elapsed_time

# ----------------- Collision detection -----------------
def detect_collisions(hash_list):
    seen = set()
    collisions = []
    for i, h in enumerate(hash_list):
        if h in seen:
            collisions.append((i, h))
        else:
            seen.add(h)
    return collisions

# ----------------- Main experiment -----------------
if __name__ == "__main__":
    num_strings = random.randint(50, 100)  # dataset size between 50-100
    dataset = generate_random_strings(num_strings)

    hash_algorithms = {
        'MD5': hashlib.md5,
        'SHA-1': hashlib.sha1,
        'SHA-256': hashlib.sha256
    }

    results = {}

    for name, func in hash_algorithms.items():
        hashes, elapsed_time = compute_hashes(dataset, func)
        collisions = detect_collisions(hashes)
        results[name] = {
            'time': elapsed_time,
            'collisions': collisions,
            'num_collisions': len(collisions)
        }

    # ----------------- Print results -----------------
    print(f"Dataset size: {len(dataset)}")
    for name, result in results.items():
        print(f"\n{name}:")
        print(f"  Time taken: {result['time']:.6f} seconds")
        print(f"  Collisions detected: {result['num_collisions']}")
        if result['num_collisions'] > 0:
            print(f"  Collision details (index, hash): {result['collisions']}")
