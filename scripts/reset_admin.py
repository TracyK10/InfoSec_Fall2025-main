#!/usr/bin/env python3
"""
Reset admin account with temporary credentials.
This script should only be used in development environments.
"""
import os
import sys
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import hmac
import struct
import base64
import hashlib

def get_db_connection():
    """Get a database connection."""
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'infosec_lab.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def generate_otps(secret_key, num_otps=10, time_step=30, digits=6):
    """Generate a list of TOTP codes."""
    if isinstance(secret_key, bytes):
        secret_key = base64.b32encode(secret_key).decode('utf-8')
    # Ensure the secret has correct padding
    secret_key = secret_key.upper() + '=' * ((8 - len(secret_key) % 8) % 8)
    
    otps = []
    current_time = int(time.time())
    
    for i in range(num_otps):
        # Calculate time step
        time_step_count = int((current_time + i * time_step) / time_step)
        
        # Convert time step to bytes
        time_step_bytes = struct.pack('>Q', time_step_count)
        
        # Generate HMAC-SHA1 hash
        key = base64.b32decode(secret_key)
        hmac_hash = hmac.new(key, time_step_bytes, hashlib.sha1).digest()
        
        # Get dynamic offset
        offset = hmac_hash[-1] & 0xf
        
        # Get the 4-byte dynamic binary code
        binary = ((hmac_hash[offset] & 0x7f) << 24 |
                 (hmac_hash[offset + 1] & 0xff) << 16 |
                 (hmac_hash[offset + 2] & 0xff) << 8 |
                 (hmac_hash[offset + 3] & 0xff))
        
        # Generate the OTP
        otp = binary % (10 ** digits)
        otps.append(f"{otp:0{digits}d}")
    
    return otps

def reset_admin(andrew_id):
    """Reset the admin account with temporary credentials."""
    # Temporary password (in a real app, this would be more secure)
    temp_password = "TempPass123!"
    hashed_pw = generate_password_hash(temp_password)
    
    # Generate a new OTP secret
    otp_secret = get_random_bytes(32)
    
    conn = get_db_connection()
    try:
        with conn:
            # Update the admin user
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password = ?, otp_secret = ? WHERE andrew_id = ?",
                (hashed_pw, otp_secret, andrew_id)
            )
            
            if cursor.rowcount == 0:
                print(f"Error: No user found with andrew_id '{andrew_id}'", file=sys.stderr)
                return False
            
            # Get the user ID
            cursor.execute("SELECT id FROM users WHERE andrew_id = ?", (andrew_id,))
            user_id = cursor.fetchone()[0]
            
            # Generate OTPs for the next 24 hours (1 per minute)
            now = datetime.now(timezone.utc)
            timestamps = [(now + timedelta(minutes=i)).strftime("%Y%m%d%H%M") 
                         for i in range(1440)]  # 24 hours * 60 minutes
            
            # Delete any existing OTPs for this user
            cursor.execute("DELETE FROM otp_chain WHERE user_id = ?", (user_id,))
            
            # Generate OTPs
            otps = generate_otps(otp_secret, num_otps=1440)
            
            # Insert OTPs into the database
            cursor.executemany(
                "INSERT INTO otp_chain (user_id, timestamp, otp_code) VALUES (?, ?, ?)",
                [(user_id, ts, otp) for ts, otp in zip(timestamps, otps)]
            )
            
            # Print the first OTP for immediate use
            print(f"First OTP: {otps[0]} (valid for 30 seconds)")
            
            # Log the change
            cursor.execute(
                """
                INSERT INTO audit_logs 
                (actor_id, actor_andrew_id, action, target_type, target_id, target_pretty, outcome)
                VALUES (?, ?, 'admin_password_reset', 'user', ?, ?, 'allowed')
                """,
                (user_id, andrew_id, user_id, f"Password reset for {andrew_id}")
            )
            
            print(f"Admin account '{andrew_id}' has been reset with temporary password: {temp_password}")
            print("You can now log in with the temporary password and use the OTP shown above for 2FA.")
            print("\nLogin steps:")
            print(f"1. Go to /login")
            print(f"2. Enter Andrew ID: {andrew_id}")
            print(f"3. Enter Password: {temp_password}")
            print(f"4. On the 2FA page, enter the OTP shown above")
            print(f"5. You will be redirected to the admin dashboard")
            
            return True
            
    except Exception as e:
        print(f"Error resetting admin account: {e}", file=sys.stderr)
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <andrew_id>", file=sys.stderr)
        sys.exit(1)
        
    andrew_id = sys.argv[1].strip().lower()
    if not andrew_id:
        print("Error: Andrew ID cannot be empty", file=sys.stderr)
        sys.exit(1)
        
    success = reset_admin(andrew_id)
    sys.exit(0 if success else 1)
