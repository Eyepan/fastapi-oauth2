import sqlite3
import bcrypt


def connection():
    return sqlite3.connect("db.sqlite3")


def initDB():
    conn = connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id VARCHAR(36) PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS salt (
            salt TEXT
        )"""
    )
    conn.commit()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM salt")
    result = cursor.fetchone()
    if not result:
        cursor.execute("INSERT INTO salt (salt) VALUES (?)", (bcrypt.gensalt(),))
    conn.commit()
    conn.close()
