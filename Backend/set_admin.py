from db import get_connection
from werkzeug.security import generate_password_hash

with get_connection() as conn:
    conn.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
        ("admin", generate_password_hash("Hemmeligt"), 1)
    )
