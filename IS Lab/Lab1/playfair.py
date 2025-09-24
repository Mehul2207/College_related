playfair_matrix = [
    ['G', 'U', 'I', 'D', 'A'],
    ['N', 'C', 'E', 'B', 'F'],
    ['H', 'K', 'L', 'M', 'O'],
    ['P', 'Q', 'R', 'S', 'T'],
    ['V', 'W', 'X', 'Y', 'Z']
]

def find_position(char, matrix):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return None

def preprocess_text(text):
    text = text.upper().replace(" ", "").replace("J", "I")
    processed_text = ""
    i = 0
    while i < len(text):
        processed_text += text[i]
        if i + 1 < len(text) and text[i] == text[i + 1]:
            processed_text += 'X'
        elif i + 1 < len(text):
            processed_text += text[i + 1]
        else:
            processed_text += 'X'
        i += 2
    return processed_text
def playfair_encrypt(plaintext, matrix):
    plaintext = preprocess_text(plaintext)
    ciphertext = ""
    for i in range(0, len(plaintext), 2):
        row1, col1 = find_position(plaintext[i], matrix)
        row2, col2 = find_position(plaintext[i + 1], matrix)
        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]

    return ciphertext
def playfair_decrypt(ciphertext, matrix):
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        row1, col1 = find_position(ciphertext[i], matrix)
        row2, col2 = find_position(ciphertext[i + 1], matrix)
        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5]
            plaintext += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1]
            plaintext += matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += matrix[row1][col2]
            plaintext += matrix[row2][col1]

    return plaintext
plaintext = "the key is hidden under the doorpad"
print(f"Original Plaintext: {plaintext}")
encrypted_text = playfair_encrypt(plaintext, playfair_matrix)
print(f"Encrypted Text: {encrypted_text}")
decrypted_text = playfair_decrypt(encrypted_text, playfair_matrix)
print(f"Decrypted Text: {decrypted_text}")