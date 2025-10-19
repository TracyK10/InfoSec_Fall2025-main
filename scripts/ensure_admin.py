"""
Script to ensure the data_admin user exists with the correct password and OTP setup.
"""
import os
import sys
import sqlite3
from datetime import datetime, timedelta
import hashlib
import hmac
import base64
from werkzeug.security import generate_password_hash

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, generate_otp_chain

def ensure_data_admin():
    """Ensure the data_admin user exists with the correct password and OTP setup."""
    andrew_id = "dataadmin"
    password = "TempPass123!"
    name = "Data Admin"
    role = "data_admin"
    secret_key = base64.b32encode(os.urandom(10)).decode('utf-8')
    
    with app.app_context():
        conn = sqlite3.connect('infosec_lab.db')
        conn.row_factory = sqlite3.Row
        
        try:
            # Check if user already exists
            user = conn.execute(
                'SELECT id, role FROM users WHERE andrew_id = ?', (andrew_id,)
            ).fetchone()
            
            if user:
                # Update existing user if needed
                if user['role'] != role:
                    conn.execute(
                        'UPDATE users SET role = ? WHERE id = ?',
                        (role, user['id'])
                    )
                    print(f"Updated existing user {andrew_id} with role {role}")
                else:
                    print(f"User {andrew_id} already exists with role {role}")
                user_id = user['id']
            else:
                # Create new user
                hashed_password = generate_password_hash(password)
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO users (name, andrew_id, password, role, otp_secret) VALUES (?, ?, ?, ?, ?)',
                    (name, andrew_id, hashed_password, role, secret_key)
                )
                user_id = cursor.lastrowid
                print(f"Created new {role} user: {andrew_id} with password: {password}")
            
            # Generate and store OTPs
            print("Generating OTP codes...")
            
            # Clear any existing OTPs for this user
            conn.execute('DELETE FROM otp_chain WHERE user_id = ?', (user_id,))
            
            # Generate new OTPs
            num_otps = 1440  # 24 hours worth of OTPs
            otps = []
            timestamp = datetime.utcnow().strftime("%Y%m%d%H%M")
            
            for i in range(num_otps):
                # Generate OTP code (6 digits)
                otp = str(int(hmac.new(
                    secret_key.encode('utf-8'),
                    timestamp.encode('utf-8'),
                    hashlib.sha256
                ).hexdigest(), 16) % 10**6).zfill(6)
                
                # Store OTP in database
                conn.execute(
                    'INSERT INTO otp_chain (user_id, timestamp, otp_code) VALUES (?, ?, ?)',
                    (user_id, timestamp, otp)
                )
                
                # Prepare next timestamp
                dt = datetime.strptime(timestamp, "%Y%m%d%H%M")
                dt += timedelta(minutes=1)
                timestamp = dt.strftime("%Y%m%d%H%M")
            
            # Commit changes
            conn.commit()
            print(f"Data admin setup complete. User ID: {user_id}")
            
        except Exception as e:
            print(f"Error setting up data admin: {e}")
            conn.rollback()
        finally:
            conn.close()

if __name__ == "__main__":
    ensure_data_admin()