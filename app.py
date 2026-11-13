import os, base64, secrets
from flask import Flask, render_template, request, jsonify
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

def buat_kunci_dari_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    kunci = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(kunci)

def enkrip_dengan_password(data_bytes, password):
    salt = secrets.token_bytes(16) # Salt acak 16 byte
    f = Fernet(buat_kunci_dari_password(password, salt))
    token = f.encrypt(data_bytes)
    # Gabungin Salt + Token biar bisa di dekrip nanti
    # Format: base64(salt) + "." + token
    return base64.urlsafe_b64encode(salt).decode() + "." + token.decode()

def dekrip_dengan_password(token_gabungan, password):
    try:
        salt_b64, token = token_gabungan.split(".", 1)
        salt = base64.urlsafe_b64decode(salt_b64)
        f = Fernet(buat_kunci_dari_password(password, salt))
        return f.decrypt(token.encode())
    except Exception:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    password = request.form.get('password', '')
    if not password:
        return jsonify({'error': 'Password wajib diisi!'}), 400

    # Kalo ada file, enkrip file. Kalo gak ada, enkrip teks
    if 'file' in request.files and request.files['file'].filename != '':
        file = request.files['file']
        data = file.read()
        hasil = enkrip_dengan_password(data, password)
        return jsonify({'result': hasil, 'filename': file.filename, 'type': 'file'})
    else:
        pesan = request.form.get('message', '')
        if not pesan:
            return jsonify({'error': 'Pesan / File wajib diisi!'}), 400
        hasil = enkrip_dengan_password(pesan.encode(), password)
        return jsonify({'result': hasil, 'type': 'text'})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    password = request.form.get('password', '')
    token = request.form.get('token', '')
    if not password or not token:
        return jsonify({'error': 'Token dan Password wajib diisi!'}), 400

    hasil_bytes = dekrip_dengan_password(token.strip(), password)
    if hasil_bytes is None:
        return jsonify({'error': 'Password salah atau Token sudah diubah!'}), 400

    # Coba baca sebagai teks, kalo gagal berarti itu file
    try:
        return jsonify({'result': hasil_bytes.decode(), 'type': 'text'})
    except:
        # Kalo file, kirim sebagai base64 biar bisa di download
        return jsonify({'result': base64.b64encode(hasil_bytes).decode(), 'type': 'file'})

if __name__ == '__main__':
    app.run(debug=True)
