def additive_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            # Shift character by key positions (A=0..Z=25)
            shifted = (ord(char) - ord('A') + key) % 26
            ciphertext += chr(shifted + ord('A'))
    return ciphertext

def additive_decrypt(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            shifted = (ord(char) - ord('A') - key) % 26
            plaintext += chr(shifted + ord('A'))
    return plaintext

# Original message
message = "I am learning information security"

# Key for additive cipher
key = 20

encrypted = additive_encrypt(message, key)
print("Encrypted message:", encrypted)

decrypted = additive_decrypt(encrypted, key)
print("Decrypted message:", decrypted)