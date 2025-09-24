from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key_hex = "0123456789ABCDEF0123456789ABCDEF"
key = bytes.fromhex(key_hex)
plaintext = "Sensitive Information".encode('utf-8')
padded_plaintext = pad(plaintext, AES.block_size)
iv = get_random_bytes(AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(padded_plaintext)

print("IV (hex):", iv.hex())
print("Ciphertext (hex):", ciphertext.hex())
decipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_padded = decipher.decrypt(ciphertext)
decrypted = unpad(decrypted_padded, AES.block_size)
print("Decrypted message:", decrypted.decode('utf-8'))