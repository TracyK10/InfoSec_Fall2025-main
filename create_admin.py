import sqlite3
import hashlib
import os
import sys
from werkzeug.security import generate_password_hash
from datetime import datetime, timezone

# Add the current directory to the path so we can import app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import DB_FILE

def create_admin_user(name, andrew_id, password):
    """
    Create a new admin user with the specified credentials.
    """
    # Use the same database path as the main application
    db_path = DB_FILE.replace('sqlite:///', '')
    db_dir = os.path.dirname(db_path)
    
    # Create the instance directory if it doesn't exist
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    print(f"Using database at: {os.path.abspath(db_path)}")
    
    try:
        # Connect to the database
        conn = sqlite3.connect(os.path.abspath(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if user already exists
        cursor.execute('SELECT id FROM users WHERE andrew_id = ?', (andrew_id,))
        if cursor.fetchone():
            print(f"Error: User with Andrew ID '{andrew_id}' already exists.")
            return False
        
        # Hash the password
        hashed_pw = generate_password_hash(password)
        
        # Insert the new admin user
        cursor.execute(
            'INSERT INTO users (name, andrew_id, password, role, created_at) VALUES (?, ?, ?, ?, ?)',
            (name, andrew_id.lower(), hashed_pw, 'user_admin', datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        )
        
        # Commit the transaction
        conn.commit()
        print(f"Successfully created admin user: {name} ({andrew_id})")
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print("Create a new admin user")
    print("======================")
    
    name = input("Enter full name: ").strip()
    andrew_id = input("Enter Andrew ID: ").strip().lower()
    password = input("Enter password: ").strip()
    
    if not all([name, andrew_id, password]):
        print("Error: All fields are required.")
    else:
        create_admin_user(name, andrew_id, password)
