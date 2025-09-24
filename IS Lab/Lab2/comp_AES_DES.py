import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

message = "Performance Testing of Encryption Algorithms".encode('utf-8')

des_key = b'A1B2C3D4'
des_iv = get_random_bytes(DES.block_size)

message_padded_des = pad(message, DES.block_size)
des_encrypt_cipher = DES.new(des_key, DES.MODE_CBC, des_iv)
des_decrypt_cipher = DES.new(des_key, DES.MODE_CBC, des_iv)

start = time.perf_counter()
des_ciphertext = des_encrypt_cipher.encrypt(message_padded_des)
des_encrypt_time = time.perf_counter() - start

start = time.perf_counter()
des_decrypted_padded = des_decrypt_cipher.decrypt(des_ciphertext)
des_decrypt_time = time.perf_counter() - start
des_decrypted = unpad(des_decrypted_padded, DES.block_size)

aes_key = get_random_bytes(32)
aes_iv = get_random_bytes(AES.block_size)
message_padded_aes = pad(message, AES.block_size)
aes_encrypt_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
aes_decrypt_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
start = time.perf_counter()
aes_ciphertext = aes_encrypt_cipher.encrypt(message_padded_aes)
aes_encrypt_time = time.perf_counter() - start

start = time.perf_counter()
aes_decrypted_padded = aes_decrypt_cipher.decrypt(aes_ciphertext)
aes_decrypt_time = time.perf_counter() - start
aes_decrypted = unpad(aes_decrypted_padded, AES.block_size)

print("\nMessage:", message.decode('utf-8'))
print("\nDES Encryption time: {:.8f} seconds".format(des_encrypt_time))
print("DES Decryption time: {:.8f} seconds".format(des_decrypt_time))
print("DES Decrypted matches original:", des_decrypted == message)

print("\nAES-256 Encryption time: {:.8f} seconds".format(aes_encrypt_time))
print("AES-256 Decryption time: {:.8f} seconds".format(aes_decrypt_time))
print("AES-256 Decrypted matches original:", aes_decrypted == message)