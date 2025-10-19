#!/usr/bin/env python3
"""
Script to promote a user to admin role.
Usage: python scripts/promote_admin.py <andrew_id> <role>
Example: python scripts/promote_admin.py jdoe user_admin
"""

import sqlite3
import sys
import os

# Adjust path to find database
DB_FILE = "infosec_lab.db"
if not os.path.exists(DB_FILE):
    DB_FILE = "../infosec_lab.db"

VALID_ROLES = ['basic', 'user_admin', 'data_admin']

def promote_user(andrew_id, role):
    """Promote a user to the specified admin role."""
    if role not in VALID_ROLES:
        print(f"[!] Invalid role. Must be one of: {', '.join(VALID_ROLES)}")
        return False
    
    if not os.path.exists(DB_FILE):
        print(f"[!] Database file '{DB_FILE}' not found.")
        return False
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Check if user exists
        user = cursor.execute(
            "SELECT id, name, andrew_id, role FROM users WHERE andrew_id = ?",
            (andrew_id,)
        ).fetchone()
        
        if not user:
            print(f"[!] User '{andrew_id}' not found in database.")
            return False
        
        old_role = user['role']
        
        # Update role
        cursor.execute(
            "UPDATE users SET role = ? WHERE andrew_id = ?",
            (role, andrew_id)
        )
        conn.commit()
        
        print(f"[✓] Successfully promoted user:")
        print(f"    Name:       {user['name']}")
        print(f"    Andrew ID:  {user['andrew_id']}")
        print(f"    Old Role:   {old_role}")
        print(f"    New Role:   {role}")
        
        return True
        
    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
        return False
    finally:
        conn.close()

def list_users():
    """List all users and their roles."""
    if not os.path.exists(DB_FILE):
        print(f"[!] Database file '{DB_FILE}' not found.")
        return
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        users = cursor.execute(
            "SELECT id, name, andrew_id, role FROM users ORDER BY id"
        ).fetchall()
        
        if not users:
            print("[!] No users found in database.")
            return
        
        print("\n[*] Current users:")
        print(f"{'ID':<5} {'Andrew ID':<20} {'Name':<25} {'Role':<15}")
        print("-" * 70)
        for user in users:
            print(f"{user['id']:<5} {user['andrew_id']:<20} {user['name']:<25} {user['role']:<15}")
        print()
        
    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) == 1 or sys.argv[1] in ['-h', '--help', 'help']:
        print("Usage:")
        print(f"  {sys.argv[0]} <andrew_id> <role>")
        print(f"  {sys.argv[0]} list")
        print()
        print("Roles:")
        print("  basic       - Regular user (default)")
        print("  user_admin  - Can manage users and roles")
        print("  data_admin  - Can manage all files")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} jdoe user_admin")
        print(f"  {sys.argv[0]} alice data_admin")
        print(f"  {sys.argv[0]} list")
        sys.exit(0)
    
    if sys.argv[1] == 'list':
        list_users()
        sys.exit(0)
    
    if len(sys.argv) != 3:
        print("[!] Error: Invalid number of arguments")
        print(f"Usage: {sys.argv[0]} <andrew_id> <role>")
        print(f"   or: {sys.argv[0]} list")
        sys.exit(1)
    
    andrew_id = sys.argv[1].lower()
    role = sys.argv[2].lower()
    
    success = promote_user(andrew_id, role)
    sys.exit(0 if success else 1)