# Script for dumping database to view its contents

import sqlite3
import os

DB_FILE = "infosec_lab.db"

if not os.path.exists(DB_FILE):
    print(f" Database file '{DB_FILE}' not found. Are you running inside Docker?")
    exit(1)

conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

print("\n Dumping database contents...\n")

tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
for t in tables:
    table = t[0]
    print(f"--- {table.upper()} ---")
    rows = cur.execute(f"SELECT * FROM {table}").fetchall()
    if not rows:
        print("(empty)")
    else:
        for row in rows:
            print(dict(row))
    print()

conn.close()