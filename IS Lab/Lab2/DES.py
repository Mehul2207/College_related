from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import time

key = b'A1B2C3D4'
plaintext = "Confidential Data".encode('utf-8')
padded_text = pad(plaintext, DES.block_size)
cipher = DES.new(key, DES.MODE_ECB)
start= time.perf_counter()
ciphertext = cipher.encrypt(padded_text)
encrypt_time= time.perf_counter()-start
print("Ciphertext (hex):", ciphertext.hex())
decrypted_padded = cipher.decrypt(ciphertext)
start=time.perf_counter()
decrypted_text = unpad(decrypted_padded, DES.block_size)
decrypt_time= time.perf_counter()-start

print("Encrypt time:{:.8f}".format(encrypt_time))
print("Decrypt time:{:.8f}".format(decrypt_time))
print("Decrypted message:", decrypted_text.decode('utf-8'))