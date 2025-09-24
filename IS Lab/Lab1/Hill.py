import numpy as np

def letter_to_number(letter):
    return ord(letter) - ord('A')

def number_to_letter(number):
    return chr(int(number) + ord('A'))

def preprocess_text(text):
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += 'X'
    return text

def matrix_multiply_mod(matrix, vector):
    result = np.dot(matrix, vector) % 26
    return result

def modular_inverse(matrix, modulus=26):
    determinant = int(np.round(np.linalg.det(matrix)))
    determinant_inv = pow(determinant, -1, modulus)
    matrix_adj = np.round(determinant * np.linalg.inv(matrix)).astype(int) % modulus
    return (determinant_inv * matrix_adj) % modulus

def hill_cipher_encrypt(plaintext, key_matrix):
    plaintext = preprocess_text(plaintext)
    encrypted_text = ""
    for i in range(0, len(plaintext), 2):
        pair = plaintext[i:i + 2]
        vector = np.array([[letter_to_number(pair[0])], [letter_to_number(pair[1])]])
        encrypted_vector = matrix_multiply_mod(key_matrix, vector)
        encrypted_text += number_to_letter(encrypted_vector[0][0]) + number_to_letter(
            encrypted_vector[1][0])

    return encrypted_text

def hill_cipher_decrypt(ciphertext, key_matrix):
    decrypted_text = ""
    inverse_matrix = modular_inverse(key_matrix)
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i + 2]
        vector = np.array([[letter_to_number(pair[0])], [letter_to_number(pair[1])]])
        decrypted_vector = matrix_multiply_mod(inverse_matrix, vector)
        decrypted_text += number_to_letter(decrypted_vector[0][0]) + number_to_letter(
            decrypted_vector[1][0])

    return decrypted_text

plaintext = "We live in an insecure world"
key_matrix = np.array([[3, 3], [2, 7]])
print(f"Original Plaintext: {plaintext}")
encrypted_text = hill_cipher_encrypt(plaintext, key_matrix)
print(f"Encrypted Text: {encrypted_text}")
decrypted_text = hill_cipher_decrypt(encrypted_text, key_matrix)
print(f"Decrypted Text: {decrypted_text}")