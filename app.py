import os
import base64
import secrets
import mimetypes
from flask import Flask, render_template, request
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # Max 20MB

# ============ KUNCI DARI PASSWORD (PBKDF2) ============
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
    salt = secrets.token_bytes(16)  # Salt acak 16 byte
    f = Fernet(buat_kunci_dari_password(password, salt))
    token = f.encrypt(data_bytes)
    # Format hasil: base64(salt) + "." + token
    # Salt boleh disebar, yang rahasia itu password nya
    return base64.urlsafe_b64encode(salt).decode() + "." + token.decode()

def dekrip_dengan_password(token_gabungan, password):
    try:
        salt_b64, token = token_gabungan.strip().split(".", 1)
        salt = base64.urlsafe_b64decode(salt_b64)
        f = Fernet(buat_kunci_dari_password(password, salt))
        return f.decrypt(token.encode())
    except Exception:
        return None

def tebak_mimetype(data_bytes, filename=""):
    # Tebak dari nama file dulu
    if filename:
        m, _ = mimetypes.guess_type(filename)
        if m:
            return m
    # Tebak dari magic bytes kalo nama file gak ada
    if data_bytes.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    if data_bytes.startswith(b'\x89PNG'):
        return 'image/png'
    if data_bytes.startswith(b'GIF8'):
        return 'image/gif'
    if data_bytes.startswith(b'RIFF') and b'WEBP' in data_bytes[:20]:
        return 'image/webp'
    if data_bytes.startswith(b'ID3') or data_bytes.startswith(b'\xff\xfb'):
        return 'audio/mpeg'
    if data_bytes.startswith(b'\x00\x00\x00') and b'ftyp' in data_bytes[:20]:
        return 'video/mp4'
    if data_bytes.startswith(b'\x1a\x45\xdf\xa3'):
        return 'video/webm'
    return 'application/octet-stream'

# ============ ROUTES ============
@app.route('/', methods=['GET', 'POST'])
def index():
    hasil = None
    mode = None
    pesan = ""
    error = None
    hasil_file = None
    hasil_filename = None
    hasil_mimetype = None

    if request.method == 'POST':
        mode = request.form.get('mode', '')
        pesan = request.form.get('pesan', '')
        password = request.form.get('password', '')

        if not password:
            error = "Password wajib diisi! Password ini yang jadi kunci brankas lu."
            return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)

        # ===== ENKRIPSI =====
        if mode == 'enkripsi':
            # 1. Kalo ada file, enkrip file
            if 'file' in request.files and request.files['file'].filename != '':
                file = request.files['file']
                file_bytes = file.read()
                # Bungkus: FILE:namafile|isi file, biar pas dekrip nama file nya balik
                payload = b"FILE:" + file.filename.encode() + b"|" + file_bytes
                hasil = enkrip_dengan_password(payload, password)
            # 2. Kalo gak ada file, enkrip teks
            elif pesan.strip() != '':
                payload = b"TEXT:" + pesan.encode()
                hasil = enkrip_dengan_password(payload, password)
            else:
                error = "Isi pesan atau pilih file dulu bro!"

        # ===== DEKRIPSI =====
        elif mode == 'dekripsi':
            if pesan.strip() == '':
                error = "Paste dulu token enkripsi nya!"
            else:
                hasil_bytes = dekrip_dengan_password(pesan, password)
                if hasil_bytes is None:
                    error = "Password salah atau Token sudah diubah / rusak!"
                else:
                    # Cek ini TEXT atau FILE
                    if hasil_bytes.startswith(b"TEXT:"):
                        hasil = hasil_bytes[5:].decode(errors='ignore')
                    elif hasil_bytes.startswith(b"FILE:"):
                        try:
                            # Pisahin nama file dan isi file
                            tanpa_prefix = hasil_bytes[5:]
                            nama_file_bytes, isi_file = tanpa_prefix.split(b"|", 1)
                            hasil_filename = nama_file_bytes.decode()
                            hasil_mimetype = tebak_mimetype(isi_file, hasil_filename)
                            # Buat Data URI biar bisa di preview & download
                            b64 = base64.b64encode(isi_file).decode()
                            hasil_file = f"data:{hasil_mimetype};base64,{b64}"
                            hasil = f"File berhasil dibuka: {hasil_filename}"
                        except Exception:
                            error = "Format file rusak!"
                    else:
                        # Buat jaga-jaga kalo token lama (sebelum update)
                        try:
                            hasil = hasil_bytes.decode()
                        except:
                            error = "Data ini bukan teks, coba cek lagi!"

    return render_template('index.html',
                           hasil=hasil,
                           mode=mode,
                           pesan=pesan,
                           error=error,
                           hasil_file=hasil_file,
                           hasil_filename=hasil_filename,
                           hasil_mimetype=hasil_mimetype)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True)
