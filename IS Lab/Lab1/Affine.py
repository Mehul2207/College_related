def mod_inverse(a, m=26):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError(f"No modular inverse for {a} mod {m}")

def affine_encrypt(plaintext, a, b):
    plaintext = plaintext.replace(" ", "").upper()
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            x = ord(char) - ord('A')
            y = (a * x + b) % 26
            ciphertext += chr(y + ord('A'))
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    a_inv = mod_inverse(a)
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            y = ord(char) - ord('A')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('A'))
    return plaintext

message = "I am learning information security"
a, b = 15, 20

encrypted = affine_encrypt(message, a, b)
print("Encrypted message:", encrypted)

decrypted = affine_decrypt(encrypted, a, b)
print("Decrypted message:", decrypted)