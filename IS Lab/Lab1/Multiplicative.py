def mod_inverse(key, mod=26):
    # Find modular inverse of key mod 26 using Extended Euclidean Algorithm
    for i in range(1, mod):
        if (key * i) % mod == 1:
            return i
    raise ValueError(f"No modular inverse for key {key} under mod {mod}")

def multiplicative_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            num = (ord(char) - ord('A'))
            encrypted_num = (num * key) % 26
            ciphertext += chr(encrypted_num + ord('A'))
    return ciphertext

def multiplicative_decrypt(ciphertext, key):
    inv_key = mod_inverse(key)
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            num = (ord(char) - ord('A'))
            decrypted_num = (num * inv_key) % 26
            plaintext += chr(decrypted_num + ord('A'))
    return plaintext

message = "I am learning information security"
key = 15

encrypted = multiplicative_encrypt(message, key)
print("Encrypted message:", encrypted)

decrypted = multiplicative_decrypt(encrypted, key)
print("Decrypted message:", decrypted)