from flask import Flask, render_template, request, send_from_directory
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import secrets  # Để tạo IV ngẫu nhiên

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

def derive_key(password):
    """Tạo khóa mã hóa/giải mã 32-byte từ mật khẩu."""
    return hashlib.sha256(password.encode()).digest()

def aes_encrypt(input_path, output_path, key):
    """Mã hóa file AES."""
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = iv + cipher.encrypt(padded_plaintext)
    with open(output_path, 'wb') as f:
        f.write(ciphertext)
    return True, None

def aes_decrypt(input_path, output_path, key):
    """Giải mã file AES."""
    try:
        with open(input_path, 'rb') as f:
            iv = f.read(AES.block_size)
            ciphertext = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        return True, None
    except Exception as e:
        return False, str(e)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/', methods=['POST'])
def process_file():
    file = request.files['file']
    key = request.form['key']
    action = request.form['action']

    if not file:
        return "No file selected.", 400
    if not key:
        return "Key cannot be empty.", 400

    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    derived_key = derive_key(key)

    if action == 'encrypt':
        encrypted_filename = f"enc_{filename}"
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
        success, error = aes_encrypt(filepath, encrypted_path, derived_key)
        if success:
            return render_template('index.html',
                                   download_url=f"/download_encrypted/{os.path.basename(encrypted_path)}",
                                   message="File encrypted successfully!")
        else:
            return render_template('index.html', error=f"Encryption failed: {error}")
    elif action == 'decrypt':
        decrypted_filename = f"dec_{filename}"
        decrypted_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)
        success, error = aes_decrypt(filepath, decrypted_path, derived_key)
        if success:
            return render_template('index.html',
                                   download_url_decrypted=f"/download_decrypted/{os.path.basename(decrypted_path)}",
                                   message="File decrypted successfully!")
        else:
            return render_template('index.html', error=f"Decryption failed: {error}")
    else:
        return "Invalid action.", 400

@app.route('/download_encrypted/<filename>')
def download_encrypted(filename):
    return send_from_directory(ENCRYPTED_FOLDER, filename, as_attachment=True)

@app.route('/download_decrypted/<filename>')
def download_decrypted(filename):
    return send_from_directory(DECRYPTED_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)