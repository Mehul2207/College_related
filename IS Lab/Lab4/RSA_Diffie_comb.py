from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
import base64
import hashlib
from random import randint

class KeyManagementSystem:
    def __init__(self):
        self.keys = {}  # store keys for subsystems

    def generate_and_store_key(self, subsystem_id):
        # Generate RSA key pair and store for subsystem
        private_key, public_key = generate_rsa_key_pair()
        self.keys[subsystem_id] = {'private_key': private_key, 'public_key': public_key}

    def get_key(self, subsystem_id):
        # Retrieve keys for a subsystem
        return self.keys.get(subsystem_id, None)

    def revoke_key(self, subsystem_id):
        # Remove keys for a subsystem
        if subsystem_id in self.keys:
            del self.keys[subsystem_id]

    def communicate(self, system1_id, system2_id, message):
        # Ensure both systems have keys
        if system1_id not in self.keys:
            self.generate_and_store_key(system1_id)
        if system2_id not in self.keys:
            self.generate_and_store_key(system2_id)

        system1_keys = self.get_key(system1_id)
        system2_keys = self.get_key(system2_id)

        # ----------------- Diffie-Hellman key exchange -----------------
        p, g = getPrime(1024), 2
        private_key1, public_key1 = generate_dh_key_pair(p, g)
        private_key2, public_key2 = generate_dh_key_pair(p, g)
        shared_secret1 = pow(public_key2, private_key1, p)
        shared_secret2 = pow(public_key1, private_key2, p)
        assert shared_secret1 == shared_secret2  # both peers have same secret

        # ----------------- Derive AES key from shared secret -----------------
        symmetric_key = derive_key(shared_secret1)

        # ----------------- Encrypt AES key using RSA -----------------
        encrypted_symmetric_key = encrypt_rsa(system2_keys['public_key'], symmetric_key)
        decrypted_symmetric_key = decrypt_rsa(system2_keys['private_key'], encrypted_symmetric_key)

        # ----------------- Encrypt and decrypt message -----------------
        encrypted_message = encrypt_symmetric(decrypted_symmetric_key, message)
        decrypted_message = decrypt_symmetric(decrypted_symmetric_key, encrypted_message)

        print(f"Original message from {system1_id} to {system2_id}: {message}")
        print(f"Encrypted message: {encrypted_message}")
        print(f"Decrypted message at {system2_id}: {decrypted_message}")

        # ----------------- Revoke keys after communication -----------------
        self.revoke_key(system1_id)
        self.revoke_key(system2_id)

# ----------------- RSA functions -----------------
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = (key.d, key.n)
    public_key = (key.e, key.n)
    return private_key, public_key

def encrypt_rsa(public_key, data):
    e, n = public_key
    encrypted_data = pow(bytes_to_long(data), e, n)
    return base64.b64encode(long_to_bytes(encrypted_data)).decode('utf-8')

def decrypt_rsa(private_key, encrypted_data):
    d, n = private_key
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    decrypted_data_int = pow(bytes_to_long(encrypted_data_bytes), d, n)
    return long_to_bytes(decrypted_data_int)

# ----------------- Symmetric AES functions -----------------
def encrypt_symmetric(key, message):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_symmetric(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_message, AES.block_size).decode('utf-8')

# ----------------- Diffie-Hellman functions -----------------
def generate_dh_key_pair(p, g):
    private_key = randint(2, p-2)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def derive_key(shared_secret):
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    return hashlib.sha256(shared_secret_bytes).digest()

# ----------------- Main -----------------
if __name__ == "__main__":
    kms = KeyManagementSystem()
    sender = input("Enter sender system ID: ")
    receiver = input("Enter receiver system ID: ")
    message = input("Enter message: ")
    kms.communicate(sender, receiver, message)
