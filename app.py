from flask import Flask, render_template, request
from cryptography.fernet import Fernet

app = Flask(__name__)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)


@app.route("/", methods=["GET", "POST"])
def index():
    hasil = ""
    mode = ""

    if request.method == "POST":
        pesan = request.form.get("pesan", "")
        mode = request.form.get("mode", "")

        if mode == "enkripsi":
            hasil = cipher.encrypt(pesan.encode()).decode()

        elif mode == "dekripsi":
            try:
                hasil = cipher.decrypt(pesan.encode()).decode()
            except Exception:
                hasil = "Pesan tidak valid atau kunci tidak sesuai."

    return render_template(
        "index.html",
        hasil=hasil,
        mode=mode
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
