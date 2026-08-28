import sqlite3

DB_NAME = "biblioteca.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    with open("schema.sql", "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print(f"Base de datos '{DB_NAME}' creada/actualizada correctamente.")

if __name__ == "__main__":
    init_db()
