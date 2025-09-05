"""
This script is used to reset the uploads directory and database for testing purposes.
It will completely remove all files from the uploads directory and reset the files table in the database.
"""
import os
import sqlite3
import shutil
from pathlib import Path

# Configuration
BASE_DIR = Path(__file__).parent.parent
UPLOAD_FOLDER = BASE_DIR / 'uploads'
DB_FILE = BASE_DIR / 'infosec_lab.db'

def reset_uploads():
    """Remove all files in the uploads directory."""
    if UPLOAD_FOLDER.exists():
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = UPLOAD_FOLDER / filename
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f'Failed to delete {file_path}. Reason: {e}')
    else:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def reset_database():
    """Reset the files table in the database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Drop the files table if it exists
        cursor.execute('''
        DROP TABLE IF EXISTS files
        ''')
        
        # Recreate the files table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            uploader_andrew_id TEXT NOT NULL,
            upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploader_andrew_id) REFERENCES users(andrew_id)
        )
        ''')
        
        conn.commit()
        print("Database reset successfully.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print("Resetting uploads and database...")
    reset_uploads()
    reset_database()
    print("Reset complete.")
