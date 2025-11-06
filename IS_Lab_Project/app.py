import os
import subprocess
from flask import Flask, request, render_template, redirect, url_for, send_file, flash, send_from_directory, abort
from werkzeug.utils import secure_filename
from encryption.classical import (
    playfair_encrypt, playfair_encrypt_with_steps,
    substitution_encrypt, caesar_encrypt, caesar_encrypt_with_steps
)
from encryption.symmetric import (
    des_encrypt_bytes, des_decrypt_bytes,
    aes_encrypt_bytes, aes_decrypt_bytes,
    count_bit_difference  # ADDED: Import new function
)
from encryption.asymmetric import (
    rsa_generate_keys, rsa_encrypt, rsa_decrypt,
    rabin_generate_keys, rabin_encrypt, rabin_decrypt,
    elgamal_generate_keys, elgamal_encrypt, elgamal_decrypt
)
from PyPDF2 import PdfReader
import docx
import io
import logging
import secrets
import binascii
import time

# -----------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------
logging.basicConfig(level=logging.DEBUG)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXT = {'pdf', 'docx'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'replace-this-secret'


# -----------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT


def extract_text_from_pdf(path):
    text = []
    with open(path, 'rb') as f:
        reader = PdfReader(f)
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text.append(page_text)
    return "\n".join(text)


def extract_text_from_docx(path):
    doc = docx.Document(path)
    return "\n".join([p.text for p in doc.paragraphs])


def generate_random_key(cipher):
    if cipher == 'des':
        return secrets.token_bytes(8)
    elif cipher == 'aes':
        key_lengths = [16, 24, 32]
        chosen_length = secrets.choice(key_lengths)
        return secrets.token_bytes(chosen_length)
    return None


def bytes_from_hex_or_string(key_str, expected_length=None):
    try:
        if key_str.lower().startswith('0x'):
            key_bytes = bytes.fromhex(key_str[2:])
        elif all(c in '0123456789abcdefABCDEF' for c in key_str.replace(' ', '')):
            key_bytes = bytes.fromhex(key_str.replace(' ', ''))
        else:
            key_bytes = key_str.encode('utf-8')

        if expected_length:
            if isinstance(expected_length, int) and len(key_bytes) != expected_length:
                raise ValueError(f"Key must be {expected_length} bytes long (got {len(key_bytes)}).")
            elif isinstance(expected_length, list) and len(key_bytes) not in expected_length:
                raise ValueError(f"Key must be one of {expected_length} bytes long (got {len(key_bytes)}).")
        return key_bytes
    except (ValueError, binascii.Error) as e:
        raise ValueError(f"Invalid key format: {str(e)}")


# ADDED: Avalanche Test Function
def run_avalanche_test(plaintext_bytes, key, cipher, trials=10):
    """Runs the Avalanche (Confusion/Diffusion) test for DES/AES."""
    encrypt_func = des_encrypt_bytes if cipher == 'des' else aes_encrypt_bytes
    block_size = 8 if cipher == 'des' else 16

    total_bits = 0
    bits_changed = 0
    original_plaintext = list(plaintext_bytes)

    # Ensure plaintext is large enough for modification/encryption
    if len(original_plaintext) < 1:
        raise ValueError("Plaintext too short to run Avalanche Test.")

    original_ciphertext = encrypt_func(plaintext_bytes, key)

    for i in range(trials):
        # 1. Flip a single bit in the plaintext. Flip the LSB of the first byte.
        modified_plaintext = list(original_plaintext)
        modified_plaintext[0] = modified_plaintext[0] ^ 1
        modified_plaintext_bytes = bytes(modified_plaintext)

        # 2. Encrypt the modified plaintext
        modified_ciphertext = encrypt_func(modified_plaintext_bytes, key)

        # 3. Compare and aggregate results (excluding IV)
        # IV length is block_size for DES, 16 for AES - IV is prepended to CT in encrypt_func
        ct1 = original_ciphertext[block_size if cipher == 'des' else 16:]
        ct2 = modified_ciphertext[block_size if cipher == 'des' else 16:]

        diff = count_bit_difference(ct1, ct2)

        min_len_ct = min(len(ct1), len(ct2))
        current_total_bits = min_len_ct * 8

        bits_changed += diff
        total_bits += current_total_bits

    if total_bits == 0:
        return {
            'cipher': cipher.upper(),
            'plain_bit_change': '1 bit (LSB of first byte)',
            'trials': trials,
            'total_bits': 0,
            'bits_changed': 0,
            'percentage': '0.00%',
            'passed': False
        }

    percentage = (bits_changed / total_bits) * 100

    # Check if the result is in the expected range for a strong cipher (45% - 55%)
    passed = 45.0 <= percentage <= 55.0

    return {
        'cipher': cipher.upper(),
        'plain_bit_change': '1 bit (LSB of first byte)',
        'trials': trials,
        'total_bits': total_bits,
        'bits_changed': bits_changed,
        'percentage': f"{percentage:.2f}%",
        'passed': passed
    }


# END ADDED: Avalanche Test Function


# -----------------------------------------------------------
# ROUTES
# -----------------------------------------------------------

@app.route('/')
def landing():
    return render_template('landing.html')


@app.route('/encrypt-decrypt')
def encrypt_decrypt():
    return render_template('encrypt.html')


@app.route('/learn')
def learn():
    return render_template('learn.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/test_mode')
def test_mode():
    """Loads the test mode page for ZAP scanning."""
    logging.debug("Rendering test_mode.html for ZAP testing.")
    try:
        return render_template('test_mode.html')
    except Exception as e:
        logging.error(f"Error rendering test_mode.html: {e}")
        flash(f"Error loading test mode page: {e}")
        return redirect(url_for('landing'))


@app.route('/images/<path:filename>')
def serve_image(filename):
    try:
        return send_from_directory('templates/images', filename)
    except FileNotFoundError:
        abort(404)


# -----------------------------------------------------------
# ENCRYPTION
# -----------------------------------------------------------
@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    cipher = request.form.get('cipher')
    key_option = request.form.get('key_option', 'default')
    key = request.form.get('key', '').strip()
    show_steps = request.form.get('show_steps')
    run_avalanche = request.form.get('run_avalanche')  # ADDED: Get avalanche flag
    input_text = request.form.get('input_text', '').strip()
    file = request.files.get('file')

    plaintext = ""

    # Handle input text or file
    if file and file.filename != '':
        if not allowed_file(file.filename):
            flash("Only .pdf or .docx files allowed")
            return redirect(url_for('encrypt_decrypt'))
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        ext = filename.rsplit('.', 1)[1].lower()
        plaintext = extract_text_from_pdf(path) if ext == 'pdf' else extract_text_from_docx(path)
        if cipher not in ['des', 'aes']:
            flash("Files can only be encrypted with DES or AES.")
            return redirect(url_for('encrypt_decrypt'))
    elif input_text:
        plaintext = input_text
    else:
        flash("Please provide input text or upload a file.")
        return redirect(url_for('encrypt_decrypt'))

    if not plaintext:
        flash("Extracted plaintext is empty. Please check the file or input text.")
        return redirect(url_for('encrypt_decrypt'))

    steps = []
    generated_key = None
    ciphertext = None
    public_key = None
    time_taken = None
    avalanche_results = None  # ADDED: Initialize avalanche results

    # Start timing
    start_time = time.perf_counter()

    try:
        # --- Classical Ciphers ---
        if cipher == 'playfair':
            if not key:
                key = 'COMPUTER'  # Use default key if none is provided and option is 'default'
            if show_steps:
                # playfair_encrypt_with_steps returns (ciphertext, steps, table), need to unpack
                ciphertext, steps, _ = playfair_encrypt_with_steps(plaintext, key)
            else:
                ciphertext = playfair_encrypt(plaintext, key)

        elif cipher == 'substitution':
            if not key:
                key = 'qwertyuiopasdfghjklzxcvbnm'
            ciphertext = substitution_encrypt(plaintext, key)

        elif cipher == 'caesar':
            if not key:
                key = '5'
            shift = int(key)
            if show_steps:
                ciphertext, steps = caesar_encrypt_with_steps(plaintext, shift)
            else:
                ciphertext = caesar_encrypt(plaintext, shift)

        # --- Symmetric Ciphers ---
        elif cipher in ['des', 'aes']:
            sym_key = None
            if key_option == 'random':
                sym_key = generate_random_key(cipher)
                generated_key = sym_key.hex()
            else:
                # Use key from form or default placeholder
                key_input = key if key else (
                    '0123456789abcdef' if cipher == 'des' else '0123456789abcdef0123456789abcdef')
                sym_key = bytes_from_hex_or_string(key_input, 8 if cipher == 'des' else [16, 24, 32])
                generated_key = sym_key.hex()

            # Run Avalanche Test if requested (must be before the final encryption)
            if run_avalanche and cipher in ['des', 'aes']:
                plaintext_bytes = plaintext.encode()
                avalanche_results = run_avalanche_test(plaintext_bytes, sym_key, cipher)

            # Perform the main encryption
            plaintext_bytes = plaintext.encode()
            if cipher == 'des':
                # Encrypt and convert to hex for display
                ciphertext = des_encrypt_bytes(plaintext_bytes, sym_key).hex()
            else:
                # Encrypt and convert to hex for display
                ciphertext = aes_encrypt_bytes(plaintext_bytes, sym_key).hex()


        # --- Asymmetric Ciphers ---
        elif cipher == 'rsa':
            private_key, public_key = rsa_generate_keys()
            ciphertext = rsa_encrypt(plaintext, public_key)
            # Public key: (e, n), Private key: (d, n)
            generated_key = f"Public (n,e): {public_key[1]},{public_key[0]} | Private (d,n): {private_key[0]},{private_key[1]}"

        elif cipher == 'rabin':
            private_key, public_key = rabin_generate_keys()
            ciphertext = rabin_encrypt(plaintext, public_key)
            # Public key: n, Private key: (p, q)
            generated_key = f"Public (n): {public_key} | Private (p,q): {private_key[0]},{private_key[1]}"

        elif cipher == 'elgamal':
            private_key, public_key = elgamal_generate_keys()
            ciphertext_tuple = elgamal_encrypt(plaintext, public_key)
            # Public key: (p, g, y), Private key: (p, g, x)
            # The ciphertext is a tuple (c1, c2), which needs to be returned as a string
            ciphertext = f"({ciphertext_tuple[0]},{ciphertext_tuple[1]})"
            generated_key = f"Public (p,g,y): {public_key[0]},{public_key[1]},{public_key[2]} | Private (p,g,x): {private_key[0]},{private_key[1]},{private_key[2]}"


        else:
            flash("Invalid cipher selected.")
            return redirect(url_for('encrypt_decrypt'))

        # End timing
        end_time = time.perf_counter()
        time_taken = f"{(end_time - start_time) * 1000:.2f} ms"

    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        flash(f"Encryption failed: {str(e)}")
        return redirect(url_for('encrypt_decrypt'))

    return render_template(
        'result.html',
        ciphertext=ciphertext,
        steps=steps,
        generated_key=generated_key,
        public_key=public_key,
        download_url=url_for('download_encrypted'),
        time_taken=time_taken,
        avalanche_results=avalanche_results  # ADDED: Pass avalanche results to template
    )


# -----------------------------------------------------------
# DOWNLOAD ENCRYPTED FILE
# -----------------------------------------------------------
@app.route('/download_encrypted', methods=['POST'])
def download_encrypted():
    ciphertext = request.form.get('ciphertext')
    if not ciphertext:
        flash("No ciphertext to download")
        return redirect(url_for('encrypt_decrypt'))

    # Convert from hex to raw bytes if possible
    try:
        binary_data = bytes.fromhex(ciphertext)
    except ValueError:
        binary_data = ciphertext.encode()

    mem = io.BytesIO(binary_data)
    mem.seek(0)
    return send_file(
        mem,
        as_attachment=True,
        download_name='encrypted.enc',
        mimetype='application/octet-stream'
    )


# -----------------------------------------------------------
# DECRYPTION
# -----------------------------------------------------------
@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    cipher = request.form.get('cipher')
    key = request.form.get('key', '').strip()
    private_key_str = request.form.get('private_key', '').strip()
    input_text = request.form.get('input_text', '').strip()
    file = request.files.get('file')

    if file and file.filename != '':
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        with open(path, 'rb') as f:
            data = f.read()
    elif input_text:
        data = input_text.encode()
    else:
        flash("Please provide ciphertext or upload a file.")
        return redirect(url_for('encrypt_decrypt'))

    plaintext = ""
    time_taken = None

    # Start timing
    start_time = time.perf_counter()

    try:
        # --- Symmetric Ciphers ---
        if cipher in ['des', 'aes']:
            try:
                # Assuming data is in binary from file upload or hex string from text input
                if file and file.filename.endswith('.enc'):
                    enc_bytes = data  # binary
                else:
                    enc_bytes = bytes.fromhex(data.decode(errors='ignore'))
            except Exception:
                enc_bytes = data  # Fallback for non-hex data if a .enc file was not used

            # Note: The expected_length for key in bytes_from_hex_or_string must be checked.
            # The function handles this, but here the input is a hex string (from generated_key) or raw string
            sym_key = bytes_from_hex_or_string(key, 8 if cipher == 'des' else [16, 24, 32])

            if cipher == 'des':
                plaintext = des_decrypt_bytes(enc_bytes, sym_key).decode(errors='ignore')
            else:
                plaintext = aes_decrypt_bytes(enc_bytes, sym_key).decode(errors='ignore')

        # --- Asymmetric Ciphers ---
        elif cipher == 'rsa':
            if not private_key_str:
                flash("Private key is required for RSA decryption.")
                return redirect(url_for('encrypt_decrypt'))
            # Format: "d,n"
            try:
                d_str, n_str = private_key_str.split(',')
                d, n = int(d_str), int(n_str)
            except ValueError:
                flash("Invalid RSA private key format. Expected 'd,n'.")
                return redirect(url_for('encrypt_decrypt'))

            plaintext = rsa_decrypt(data.decode(errors='ignore'), (d, n))

        elif cipher == 'rabin':
            if not private_key_str:
                flash("Private key (p,q) is required for Rabin decryption.")
                return redirect(url_for('encrypt_decrypt'))
            # Format: "p,q"
            try:
                p_str, q_str = private_key_str.split(',')
                p, q = int(p_str), int(q_str)
            except ValueError:
                flash("Invalid Rabin private key format. Expected 'p,q'.")
                return redirect(url_for('encrypt_decrypt'))

            plaintext = rabin_decrypt(data.decode(errors='ignore'), (p, q))

        elif cipher == 'elgamal':
            if not private_key_str:
                flash("Private key (p,g,x) is required for ElGamal decryption.")
                return redirect(url_for('encrypt_decrypt'))
            # Format: "p,g,x"
            try:
                p, g, x = map(int, private_key_str.split(','))
            except ValueError:
                flash("Invalid ElGamal private key format. Expected 'p,g,x'.")
                return redirect(url_for('encrypt_decrypt'))

            # Ciphertext is expected as a string representation of a tuple: "(c1,c2)"
            ciphertext_tuple_str = data.decode(errors='ignore').strip()
            try:
                c1_str, c2_str = ciphertext_tuple_str.strip('()').split(',')
                ciphertext_tuple = (int(c1_str), int(c2_str))
            except Exception:
                flash("Invalid ElGamal ciphertext format. Expected '(c1,c2)'.")
                return redirect(url_for('encrypt_decrypt'))

            plaintext = elgamal_decrypt(ciphertext_tuple, (p, g, x))

        else:
            flash("Unsupported cipher for decryption.")
            return redirect(url_for('encrypt_decrypt'))

        # End timing
        end_time = time.perf_counter()
        time_taken = f"{(end_time - start_time) * 1000:.2f} ms"

        if not plaintext or plaintext.isspace():
            flash("Decryption failed: No valid plaintext recovered.")
            return redirect(url_for('encrypt_decrypt'))

    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        flash(f"Decryption failed: {str(e)}")
        return redirect(url_for('encrypt_decrypt'))

    return render_template('result.html', plaintext=plaintext, steps=[], generated_key=None, download_url=None,
                           time_taken=time_taken)


# -----------------------------------------------------------
# ZAP SECURITY TESTING
# -----------------------------------------------------------
@app.route('/run_zap_scan', methods=['GET'])
def run_zap_scan():
    """Runs OWASP ZAP scan on the /test_mode endpoint and returns the report."""
    try:
        api_key = "12345"  # Replace with your actual ZAP API key
        os.makedirs("reports", exist_ok=True)

        # Run zap_scan.py as a subprocess
        subprocess.run([
            "python", "zap_scan.py", "http://localhost:5000/test_mode", api_key
        ], check=True)

        report_path = os.path.join("reports", "zap_report.html")
        if not os.path.exists(report_path):
            flash("ZAP scan completed, but report file not found.")
            return redirect(url_for('test_mode'))

        return send_file(
            report_path,
            as_attachment=True,
            download_name='zap_test_mode_report.html'
        )

    except subprocess.CalledProcessError as e:
        logging.error(f"ZAP scan failed: {e}")
        flash(f"ZAP scan failed: {e}")
        return redirect(url_for('test_mode'))
    except Exception as e:
        logging.error(f"Error running ZAP scan: {e}")
        flash(f"ZAP scan error: {str(e)}")
        return redirect(url_for('test_mode'))


# -----------------------------------------------------------
# MAIN
# -----------------------------------------------------------
if __name__ == '__main__':
    os.makedirs("reports", exist_ok=True)
    app.run(debug=True, port=5000)