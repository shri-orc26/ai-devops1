import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
""")

cursor.executemany(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    [
        ("admin", generate_password_hash("admin123")),
        ("user1", generate_password_hash("pass123")),
    ],
)

conn.commit()
conn.close()
print("Database created successfully!")