import os
import base64
from flask import Flask, render_template, request
from cryptography.fernet import Fernet

app = Flask(__name__)

KEY_ENV = os.environ.get("FERNET_KEY")
if KEY_ENV:
    KEY = KEY_ENV.encode()
else:
    KEY = Fernet.generate_key()
    print("=" * 50)
    print("KUNCI BARU KAMU (COPY KE VERCEL):")
    print(KEY.decode())
    print("=" * 50)

cipher = Fernet(KEY)

@app.route("/", methods=["GET", "POST"])
def index():
    hasil = ""
    mode = ""
    hasil_file = None
    hasil_filename = ""
    hasil_mimetype = ""

    if request.method == "POST":
        mode = request.form.get("mode", "")
        pesan = request.form.get("pesan", "").strip()
        file = request.files.get("file")

        #FILE (GAMBAR / AUDIO / VIDEO) ===
        if file and file.filename != "":
            data = file.read()
            if len(data) > 20 * 1024 * 1024:
                hasil = "File terlalu besar, maks 20MB."
            elif mode == "enkripsi":
                try:
                    header = f"{file.filename}|{file.mimetype}|".encode()
                    payload = header + data
                    hasil = cipher.encrypt(payload).decode()
                except Exception:
                    hasil = "Gagal mengenkripsi file."
            elif mode == "dekripsi":
                hasil = "Untuk dekripsi file, paste token nya di kolom pesan, jangan upload file lagi."
        
        # === KALO CUMA TEKS / TOKEN ===
        else:
            if len(pesan) > 1000000:
                hasil = "Pesan terlalu panjang."
            elif not pesan:
                hasil = "Pesan tidak boleh kosong."
            elif mode == "enkripsi":
                try:
                    hasil = cipher.encrypt(pesan.encode()).decode()
                except Exception:
                    hasil = "Gagal mengenkripsi pesan."
            elif mode == "dekripsi":
                try:
                    decrypted = cipher.decrypt(pesan.encode())
                    try:
                        parts = decrypted.split(b"|", 2)
                        if len(parts) == 3:
                            fname = parts[0].decode()
                            fmime = parts[1].decode()
                            fdata = parts[2]
                            if "/" in fmime:
                                hasil = f"File berhasil didekripsi: {fname}"
                                hasil_filename = fname
                                hasil_mimetype = fmime
                                b64 = base64.b64encode(fdata).decode()
                                hasil_file = f"data:{fmime};base64,{b64}"
                            else:
                                raise ValueError("Bukan file")
                        else:
                            raise ValueError("Bukan file")
                    except Exception:
                        hasil = decrypted.decode()
                except Exception:
                    hasil = "Pesan tidak valid atau kunci tidak sesuai."
            else:
                hasil = "Mode tidak dikenali."

    return render_template("index.html", hasil=hasil, mode=mode, hasil_file=hasil_file, hasil_filename=hasil_filename, hasil_mimetype=hasil_mimetype)
    
@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":
    is_debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="127.0.0.1", port=5000, debug=is_debug)
