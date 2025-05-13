import sqlite3

DB_NAME = "shopping.db"

# Funktion der returnerer en ny databaseforbindelse
def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Gør det muligt at tilgå kolonner med navne
    return conn

# Funktion der opretter de nødvendige tabeller
def init_db():
    with get_connection() as conn:
        # Tabel til varer
        conn.execute('''
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL COLLATE NOCASE,
                comment TEXT,
                bought BOOLEAN DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, bought)
            )
        ''')

        # Tabel til brugere
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0
            )
        ''')
