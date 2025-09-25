from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from pypdf import PdfReader
import time

def read_pdf_text(file_path):
    reader = PdfReader(file_path)
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
    return text

def menu():
    print("Which cryptography would you like to use?")
    print("1.AES")
    print("2.DES")
    print("3.Rabin cryptosystem")
    choice=input("What would you like to do?")
    if choice=="1":
        AES_works(data)
    if choice=="2":
        DES_works(data)

def DES_works(data):
    key = b'A1B2C3D4'
    plaintext = data.encode('utf-8')
    padded_text = pad(plaintext, DES.block_size)
    cipher = DES.new(key, DES.MODE_ECB)
    start = time.perf_counter()
    ciphertext = cipher.encrypt(padded_text)
    encrypt_time = time.perf_counter() - start
    print("Ciphertext (hex):", ciphertext.hex())
    decrypted_padded = cipher.decrypt(ciphertext)
    start = time.perf_counter()
    decrypted_text = unpad(decrypted_padded, DES.block_size)
    decrypt_time = time.perf_counter() - start
    print("Encrypt time:{:.8f}".format(encrypt_time))
    print("Decrypt time:{:.8f}".format(decrypt_time))
    print("Decrypted message:", decrypted_text.decode('utf-8'))

def AES_works(data):
    key_hex = "0123456789ABCDEF0123456789ABCDEF"
    key = bytes.fromhex(key_hex)
    plaintext = data.encode('utf-8')
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

file_path=input("Enter the file path: ").strip('"')
data=read_pdf_text(file_path)

menu()
