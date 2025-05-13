from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from db import get_connection, init_db  # Henter funktioner fra db.py

# 🔧 Konfigurer Flask-appen
app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "bdd07127e6a6641d1f1d28f3adcdd543b3d92beae7d21ff0fa9b2f4f3384ae8f"  # Erstat med noget stærkt i produktion
app.config["SESSION_COOKIE_HTTPONLY"] = True       # Beskyt mod adgang via JavaScript
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"      # Forhindrer CSRF på tværs af domæner
# app.config["SESSION_COOKIE_SECURE"] = True       # Brug hvis du hoster med HTTPS
Session(app)

# 🌐 Tillad frontend-adgang (CORS)
CORS(app, supports_credentials=True)


# 🏗️ Initialiser database og tabeller
init_db()

# 🛡️ Hjælpefunktion: Er brugeren admin?
def is_admin():
    username = session.get("username")
    if not username:
        return False
    with get_connection() as conn:
        user = conn.execute("SELECT is_admin FROM users WHERE username = ?", (username,)).fetchone()
        return user and user["is_admin"]

# 📦 GET: Hent alle varer i listen (kræver login)
@app.route("/items", methods=["GET"])
def get_items():
    if "user_id" not in session:
        return {"error": "Login krævet"}, 401

    with get_connection() as conn:
        items = conn.execute("SELECT * FROM items ORDER BY id DESC").fetchall()
        return jsonify([dict(row) for row in items])

# ➕ POST: Tilføj ny vare
@app.route("/items", methods=["POST"])
def add_item():
    data = request.get_json()
    name = data.get("name", "").strip()
    comment = data.get("comment", "").strip()

    if not name:
        return {"error": "Varenavn mangler"}, 400

    try:
        with get_connection() as conn:
            cur = conn.execute(
                "INSERT INTO items (name, comment) VALUES (?, ?)",
                (name, comment)
            )
            new_id = cur.lastrowid
            item = conn.execute("SELECT * FROM items WHERE id = ?", (new_id,)).fetchone()
            return jsonify(dict(item)), 201
    except sqlite3.IntegrityError:
        return {"error": "Varen findes allerede på listen"}, 409

# 🔁 PUT: Toggle købt/ikke købt
@app.route("/items/<int:item_id>", methods=["PUT"])
def toggle_bought(item_id):
    with get_connection() as conn:
        item = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if item is None:
            return {"error": "Vare ikke fundet"}, 404

        new_status = not bool(item["bought"])

        try:
            conn.execute(
                "UPDATE items SET bought = ? WHERE id = ?",
                (new_status, item_id)
            )
            updated = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
            return jsonify(dict(updated))
        except sqlite3.IntegrityError:
            return {"error": "Dublet – kunne ikke ændre status"}, 409

# 🗑️ DELETE: Slet købte eller alle varer
@app.route("/items", methods=["DELETE"])
def delete_items():
    bought = request.args.get("bought")
    all_items = request.args.get("all")

    with get_connection() as conn:
        if all_items == "true":
            conn.execute("DELETE FROM items")
            return {"message": "Alle varer slettet"}, 200
        elif bought == "true":
            conn.execute("DELETE FROM items WHERE bought = 1")
            return {"message": "Købte varer slettet"}, 200
        else:
            return {"error": "Ingen gyldig sletteparameter angivet"}, 400

# 👤 POST: Opret ny bruger (kun admin)
@app.route("/register", methods=["POST"])
def register():
    if not is_admin():
        return {"error": "Kun admin må oprette brugere"}, 403

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    is_admin_flag = data.get("is_admin", False)

    if not username or not password:
        return {"error": "Brugernavn og adgangskode er påkrævet"}, 400

    password_hash = generate_password_hash(password)

    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (username, password_hash, int(bool(is_admin_flag)))
            )
        return {"message": "Bruger oprettet"}, 201
    except sqlite3.IntegrityError:
        return {"error": "Brugernavn findes allerede"}, 409

# 🔐 POST: Login
@app.route("/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return {"message": "Du er logget ud"}

# 🔎 GET: Returnér om den aktuelle bruger er admin
@app.route("/is-admin")
def check_admin():
    return {"is_admin": bool(is_admin())}

# 🔁 POST: Admin ændrer adgangskode for en bruger
@app.route("/update-password", methods=["POST"])
def update_password():
    if not is_admin():
        return {"error": "Kun admin må ændre kodeord"}, 403

    data = request.get_json()
    username = data.get("username")
    new_password = data.get("password")

    if not username or not new_password:
        return {"error": "Ugyldige input"}, 400
    if len(username) < 3 or len(new_password) < 4:
        return {"error": "Brugernavn skal være mindst 3 tegn og kode mindst 4"}, 400

    password_hash = generate_password_hash(new_password)

    with get_connection() as conn:
        result = conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (password_hash, username)
        )
        if result.rowcount == 0:
            return {"error": "Bruger ikke fundet"}, 404

    return {"message": "Kodeord opdateret"}

# ▶️ Kør serveren lokalt, hvis scriptet køres direkte
if __name__ == "__main__":
    app.run(debug=True)
