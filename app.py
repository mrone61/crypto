import os
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
    if request.method == "POST":
        pesan = request.form.get("pesan", "").strip()
        mode = request.form.get("mode", "")
        if len(pesan) > 500:
            hasil = "Pesan terlalu panjang, maks 500 karakter."
        elif not pesan:
            hasil = "Pesan tidak boleh kosong."
        elif mode == "enkripsi":
            try:
                hasil = cipher.encrypt(pesan.encode()).decode()
            except Exception:
                hasil = "Gagal mengenkripsi pesan."
        elif mode == "dekripsi":
            try:
                hasil = cipher.decrypt(pesan.encode()).decode()
            except Exception:
                hasil = "Pesan tidak valid atau kunci tidak sesuai."
        else:
            hasil = "Mode tidak dikenali."
    return render_template("index.html", hasil=hasil, mode=mode)
    
@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":
    is_debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="127.0.0.1", port=5000, debug=is_debug)
