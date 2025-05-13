from flask import Flask, request, jsonify
from flask_cors import CORS
from db import get_connection, init_db  # Funktioner fra db.py
import sqlite3
from flask import session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

# Opret Flask-applikationen
app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "hemmelig_nøgle"  # udskift med noget stærkere i praksis
Session(app)

# Tillad adgang fra andre domæner (f.eks. din React frontend på localhost:3000)
CORS(app)

# Initialiser database og opret tabel hvis den ikke findes
init_db()

# Endpoint: Hent alle varer fra databasen
@app.route("/items", methods=["GET"])
def get_items():
    with get_connection() as conn:
        if "user_id" not in session:
            return {"error": "Login krævet"}, 401

        # Hent alle rækker fra tabellen "items"
        items = conn.execute("SELECT * FROM items ORDER BY id DESC").fetchall()
        # Omform resultatet til JSON-venligt format (liste af dicts)
        return jsonify([dict(row) for row in items])

# Endpoint: Tilføj ny vare til databasen
@app.route("/items", methods=["POST"])
def add_item():
    data = request.get_json()  # Læs JSON-body fra frontend
    name = data.get("name", "").strip()
    comment = data.get("comment", "").strip()

    # Tjek at varenavn ikke er tomt
    if not name:
        return {"error": "Varenavn mangler"}, 400

    try:
        with get_connection() as conn:
            # Forsøg at indsætte varen i databasen
            cur = conn.execute(
                "INSERT INTO items (name, comment) VALUES (?, ?)",
                (name, comment)
            )
            # Find den indsatte række via ID
            new_id = cur.lastrowid
            item = conn.execute("SELECT * FROM items WHERE id = ?", (new_id,)).fetchone()
            return jsonify(dict(item)), 201  # Send nyoprettet vare tilbage
    except sqlite3.IntegrityError:
        # Hvis varen allerede findes (pga. UNIQUE constraint), returnér 409
        return {"error": "Varen findes allerede på listen"}, 409

# Endpoint: Skift status på en vare (købt/ikke købt)
@app.route("/items/<int:item_id>", methods=["PUT"])
def toggle_bought(item_id):
    with get_connection() as conn:
        # Find varen i databasen
        item = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if item is None:
            return {"error": "Vare ikke fundet"}, 404

        # Skift status til det modsatte af nuværende (True ↔ False)
        new_status = not bool(item["bought"])

        try:
            # Opdater vare med ny status
            conn.execute(
                "UPDATE items SET bought = ? WHERE id = ?",
                (new_status, item_id)
            )
            # Hent den opdaterede vare og returnér den
            updated = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
            return jsonify(dict(updated))
        except sqlite3.IntegrityError:
            # Fejl hvis den nye status ville give dublet (f.eks. “æg” som ikke købt findes allerede)
            return {"error": "Dublet – kunne ikke ændre status"}, 409

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
# Kør Flask-serveren hvis filen køres direkte
if __name__ == "__main__":
    app.run(debug=True)

@app.route("/auth/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return {"error": "Brugernavn og adgangskode kræves"}, 400

    hashed_pw = generate_password_hash(password)

    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hashed_pw)
            )
        return {"message": "Bruger oprettet"}, 201
    except sqlite3.IntegrityError:
        return {"error": "Brugernavn eksisterer allerede"}, 409

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    with get_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if user and check_password_hash(user["password_hash"], password):
        session["user_id"] = user["id"]
        return {"message": "Login succesfuld"}
    else:
        return {"error": "Ugyldigt login"}, 401

@app.route("/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return {"message": "Du er logget ud"}

