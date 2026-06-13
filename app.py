from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import os
import uuid

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
DECRYPTED_FOLDER = "decrypted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# ============================================
# Generate AES Key
# ============================================

def generate_key(password, salt):
    return scrypt(password, salt, 32, N=2**14, r=8, p=1)

# ============================================
# Encrypt API
# ============================================

@app.route('/encrypt', methods=['POST'])
def encrypt_image():

    if 'image' not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    image = request.files['image']
    password = request.form.get("password")

    if not password:
        return jsonify({"error": "Password required"}), 400

    # Save uploaded image
    filename = str(uuid.uuid4()) + "_" + image.filename
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    image.save(input_path)

    # Read image bytes
    with open(input_path, "rb") as f:
        data = f.read()

    salt = get_random_bytes(16)
    iv = get_random_bytes(16)

    key = generate_key(password.encode(), salt)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        filename + ".bin"
    )

    with open(encrypted_path, "wb") as f:
        f.write(salt + iv + encrypted_data)

    return send_file(
    encrypted_path,
    as_attachment=True,
    download_name=image.filename + ".bin"
)

# ============================================
# Decrypt API
# ============================================

@app.route('/decrypt', methods=['POST'])
def decrypt_image():

    if 'file' not in request.files:
        return jsonify({"error": "No encrypted file uploaded"}), 400

    enc_file = request.files['file']
    password = request.form.get("password")

    if not password:
        return jsonify({"error": "Password required"}), 400

    filename = str(uuid.uuid4()) + "_" + enc_file.filename

    encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename)

    enc_file.save(encrypted_path)

    with open(encrypted_path, "rb") as f:
        file_data = f.read()

    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    key = generate_key(password.encode(), salt)

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(
            cipher.decrypt(encrypted_data),
            AES.block_size
        )

        output_path = os.path.join(
            DECRYPTED_FOLDER,
            filename.replace(".bin", "")
        )

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        return send_file(
            output_path,
            as_attachment=True
        )

    except:
        return jsonify({
            "error": "Invalid password or corrupted file"
        }), 400

# ============================================
# Run Server
# ============================================

if __name__ == '__main__':
    app.run(debug=True, port=5000)