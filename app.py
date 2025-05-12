import os
import base64
import json
from flask import Flask, request, jsonify, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from werkzeug.utils import secure_filename
import hashlib
from flask_cors import CORS
from stegano import lsb
from io import BytesIO
from PIL import Image

app = Flask(__name__, static_folder='build')
CORS(app)

# Configuration
SECURE_STORAGE = "secure_storage"
TEMP_STORAGE = os.path.join(SECURE_STORAGE, "temp")
KEYS_FILE = "keys.json"
PASSWORD_SALT = b"fixed_salt_for_hashing"  # In production, use random salt
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}

# Ensure directories exist
os.makedirs(SECURE_STORAGE, exist_ok=True)
os.makedirs(TEMP_STORAGE, exist_ok=True)

# ---- Helper Functions ----
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def verify_password(password):
    """Check if password matches stored hash"""
    try:
        with open(KEYS_FILE, "r") as f:
            keys = json.load(f)
            stored_hash = keys.get("password_hash")
            if not stored_hash:
                return False
            
            provided_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                PASSWORD_SALT,
                100000
            ).hex()
            return provided_hash == stored_hash
    except FileNotFoundError:
        return False

def derive_key(password):
    """Generate encryption key from password"""
    return PBKDF2(
        password,
        PASSWORD_SALT,
        dkLen=32,  # 32 bytes = 256 bits for AES-256
        count=100000,
        hmac_hash_module=SHA256
    )

# ---- Password Management ----
@app.route('/set_master_password', methods=['POST'])
def set_master_password():
    """Initialize password for encryption"""
    password = request.json.get("password")
    if not password:
        return jsonify({"error": "Password required"}), 400

    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        PASSWORD_SALT,
        100000
    ).hex()

    with open(KEYS_FILE, "w") as f:
        json.dump({"password_hash": password_hash}, f)

    return jsonify({"message": "Master password set"})

# ---- File Encryption ----
@app.route('/encrypt_file', methods=['POST'])
def encrypt_file():
    """Encrypt file with password"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    password = request.form.get("password")
    
    if not password or not verify_password(password):
        return jsonify({"error": "Invalid password"}), 401

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        # Generate encryption key from password
        key = derive_key(password)
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Encrypt file data
        file_data = file.read()
        encrypted_data = iv + cipher.encrypt(pad(file_data, AES.block_size))

        # Create in-memory file for response
        mem_file = BytesIO(encrypted_data)
        mem_file.seek(0)

        return send_file(
            mem_file,
            as_attachment=True,
            download_name=f"encrypted_{file.filename}",
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

# ---- File Decryption ----
@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    """Decrypt file with password"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    password = request.form.get("password")
    
    if not password or not verify_password(password):
        return jsonify({"error": "Invalid password"}), 401

    try:
        # Generate decryption key from password
        key = derive_key(password)
        encrypted_data = file.read()

        # Extract IV (first 16 bytes)
        iv = encrypted_data[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt data
        decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)

        # Create in-memory file for response
        mem_file = BytesIO(decrypted_data)
        mem_file.seek(0)

        return send_file(
            mem_file,
            as_attachment=True,
            download_name=f"decrypted_{file.filename}",
            mimetype='application/octet-stream'
        )
    except ValueError as e:
        return jsonify({"error": "Decryption failed - wrong password or corrupted file"}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption error: {str(e)}"}), 500

# ---- Image Steganography ----
@app.route('/hide_message', methods=['POST'])
def hide_message():
    """Hide message in image"""
    if 'file' not in request.files:
        return jsonify({"error": "No image provided"}), 400
    
    image_file = request.files['file']
    message = request.form.get("message")

    if not message:
        return jsonify({"error": "Message is required"}), 400

    if not allowed_file(image_file.filename):
        return jsonify({"error": "Only PNG/JPG images allowed"}), 400

    try:
        # Save image to temporary file
        temp_path = os.path.join(TEMP_STORAGE, secure_filename(image_file.filename))
        image_file.save(temp_path)

        # Hide message using LSB steganography
        secret = lsb.hide(temp_path, message)
        
        # Convert to bytes for response
        output = BytesIO()
        secret.save(output, format="PNG")
        output.seek(0)

        # Clean up
        os.remove(temp_path)

        return send_file(
            output,
            as_attachment=True,
            download_name=f"secret_{image_file.filename}",
            mimetype='image/png'
        )
    except Exception as e:
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": f"Failed to hide message: {str(e)}"}), 500

@app.route('/reveal_message', methods=['POST'])
def reveal_message():
    """Extract hidden message from image"""
    if 'file' not in request.files:
        return jsonify({"error": "No image provided"}), 400
    
    image_file = request.files['file']

    try:
        # Save image to temporary file
        temp_path = os.path.join(TEMP_STORAGE, secure_filename(image_file.filename))
        image_file.save(temp_path)

        # Reveal hidden message
        hidden_msg = lsb.reveal(temp_path)

        # Clean up
        os.remove(temp_path)

        if hidden_msg:
            return jsonify({"message": hidden_msg})
        return jsonify({"error": "No hidden message found"}), 404
    except Exception as e:
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": f"Failed to reveal message: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')