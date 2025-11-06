import string

def clean_text(text):
    return ''.join(c for c in text.lower() if c.isalpha())

### ---------------- CAESAR ---------------- ###
def caesar_encrypt(plaintext, shift=3):
    return ''.join(
        chr((ord(ch) - ord('A' if ch.isupper() else 'a') + shift) % 26 + ord('A' if ch.isupper() else 'a'))
        if ch.isalpha() else ch for ch in plaintext
    )

def caesar_encrypt_with_steps(plaintext, shift=3):
    steps = []
    ciphertext = []
    for ch in plaintext:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            original_pos = ord(ch) - ord(base)
            new_pos = (original_pos + shift) % 26
            enc = chr(new_pos + ord(base))
            ciphertext.append(enc)
            steps.append(f"{ch} → {enc} (shift {shift})")
        else:
            ciphertext.append(ch)
    return ''.join(ciphertext), steps

### ---------------- SUBSTITUTION ---------------- ###
def substitution_encrypt(plaintext, key_alphabet):
    key_alphabet = key_alphabet.lower()
    if len(key_alphabet) != 26:
        raise ValueError("Substitution key must be 26 letters")
    mapping = {c: k for c, k in zip(string.ascii_lowercase, key_alphabet)}
    out = []
    for ch in plaintext:
        if ch.isalpha():
            low = ch.lower()
            enc = mapping[low]
            out.append(enc.upper() if ch.isupper() else enc)
        else:
            out.append(ch)
    return ''.join(out)

### ---------------- PLAYFAIR ---------------- ###
def generate_playfair_table(key):
    key = ''.join(dict.fromkeys(key.lower().replace('j', 'i')))
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    table = []
    used = set()
    for ch in key + alphabet:
        if ch not in used and ch.isalpha():
            used.add(ch)
            table.append(ch)
    return [table[i * 5:(i + 1) * 5] for i in range(5)]

def playfair_encrypt(plaintext, key='keyword'):
    text = clean_text(plaintext).replace('j', 'i')
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else 'x'
        if a == b:
            pairs.append(a + 'x')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    table = generate_playfair_table(key)
    pos = {table[r][c]: (r, c) for r in range(5) for c in range(5)}
    cipher = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            cipher.append(table[ra][(ca + 1) % 5])
            cipher.append(table[rb][(cb + 1) % 5])
        elif ca == cb:
            cipher.append(table[(ra + 1) % 5][ca])
            cipher.append(table[(rb + 1) % 5][cb])
        else:
            cipher.append(table[ra][cb])
            cipher.append(table[rb][ca])
    return ''.join(cipher)

def playfair_encrypt_with_steps(plaintext, key='keyword'):
    text = clean_text(plaintext).replace('j', 'i')
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else 'x'
        if a == b:
            pairs.append(a + 'x')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    table = generate_playfair_table(key)
    pos = {table[r][c]: (r, c) for r in range(5) for c in range(5)}
    cipher = []
    steps = [f"Plaintext processed into digraphs: {', '.join(pairs)}"]
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            enc_a = table[ra][(ca + 1) % 5]
            enc_b = table[rb][(cb + 1) % 5]
            cipher.append(enc_a)
            cipher.append(enc_b)
            steps.append(f"Digraph {a}{b} → {enc_a}{enc_b} (same row, shift right)")
        elif ca == cb:
            enc_a = table[(ra + 1) % 5][ca]
            enc_b = table[(rb + 1) % 5][cb]
            cipher.append(enc_a)
            cipher.append(enc_b)
            steps.append(f"Digraph {a}{b} → {enc_a}{enc_b} (same column, shift down)")
        else:
            enc_a = table[ra][cb]
            enc_b = table[rb][ca]
            cipher.append(enc_a)
            cipher.append(enc_b)
            steps.append(f"Digraph {a}{b} → {enc_a}{enc_b} (rectangle rule, swap columns)")
    return ''.join(cipher), steps, table