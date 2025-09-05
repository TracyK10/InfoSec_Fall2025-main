"""
Information Security Fall 2025 Lab - Flask Application
-----------------------------------------------------
Short description: Minimal course-branded web app that supports registration
(Name, Andrew ID, Password), login, session-based greeting, and logout.
Includes a landing page and CMU-themed styling.

Routes:
- GET /          : Landing page with welcome message + Login/Register buttons.
- GET/POST /register : Register with name, Andrew ID, and password; on success redirect to /login.
- GET/POST /login    : Login with Andrew ID + password; on success redirect to /dashboard.
- GET /dashboard     : Greets authenticated user: "Hello {Name}, Welcome to Lab 0 of Information Security course. Enjoy!!!"
- GET /logout        : Clear session and return to landing page.
"""
from flask import Flask, request, redirect, render_template, session, url_for, flash, send_from_directory, abort
import sqlite3, os
from datetime import datetime
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "change-me-in-production")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "infosec_lab.db")

# ---------------- Database Helpers ----------------
def get_db():
    """Open a connection to SQLite with Row access."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database by executing schema.sql (single source of truth)."""
    schema_path = os.path.join(BASE_DIR, "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    conn = get_db()
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()

# Ensure database is initialized at import time
os.makedirs(BASE_DIR, exist_ok=True)
init_db()

# ---------------- Utility ----------------
def current_user():
    """Return the current logged-in user row or None."""
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return user

# ---------------- Routes ----------------
@app.route("/")
def index():
    """Landing page with CMU-themed welcome and CTA buttons."""
    return render_template("index.html", title="Information Security Fall 2025 Lab", user=current_user())

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register: capture name, Andrew ID, and password; redirect to login on success."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        # Basic validation
        if not name or not andrew_id or not password:
            flash("All fields are required.", "error")
            return render_template("register.html", title="Register")

        conn = get_db()
        try:
            conn.execute(
                f"INSERT INTO users (name, andrew_id, password) VALUES ('{name}', '{andrew_id}', '{password}')"
            )
            conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That Andrew ID is already registered.", "error")
            return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
        finally:
            conn.close()
    # GET
    return render_template("register.html", title="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login with Andrew ID and password; redirect to dashboard on success."""
    if request.method == "POST":
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        query = f"SELECT * FROM users WHERE andrew_id = '{andrew_id}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("dashboard"))
        flash("Invalid Andrew ID or password.", "error")
    return render_template("login.html", title="Login")


@app.route("/dashboard")
def dashboard():
    """Dashboard page with file upload form and list of all files."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Get all files from database
    conn = get_db()
    files = conn.execute(
        "SELECT * FROM files ORDER BY upload_timestamp DESC"
    ).fetchall()
    conn.close()
    
    return render_template("dashboard.html", 
                         title="Dashboard", 
                         user=user,
                         files=files)

@app.route("/uploads/<path:filename>")
def download_file(filename):
    """Serve uploaded files for download."""
    return send_from_directory(os.path.join(BASE_DIR, 'uploads'), filename, as_attachment=True)

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file uploads."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))
    
    if file:
        # Generate a unique filename to prevent collisions
        original_filename = file.filename
        file_ext = os.path.splitext(original_filename)[1]
        stored_filename = f"{uuid.uuid4().hex}{file_ext}"
        
        # Save file to uploads directory
        file.save(os.path.join(BASE_DIR, 'uploads', stored_filename))
        
        # Save file metadata to database
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO files (filename, stored_filename, uploader_andrew_id) VALUES (?, ?, ?)",
                (original_filename, stored_filename, user['andrew_id'])
            )
            conn.commit()
            flash('File uploaded successfully!', 'success')
        except Exception as e:
            flash('Error uploading file', 'error')
        finally:
            conn.close()
    
    return redirect(url_for('dashboard'))

@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    """Delete a file."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    conn = get_db()
    try:
        # Get file info
        file_info = conn.execute(
            "SELECT stored_filename FROM files WHERE id = ?", (file_id,)
        ).fetchone()
        
        if file_info:
            # Delete file from filesystem
            file_path = os.path.join(BASE_DIR, 'uploads', file_info['stored_filename'])
            if os.path.exists(file_path):
                os.remove(file_path)
            
            # Delete record from database
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
            flash('File deleted successfully!', 'success')
        else:
            flash('File not found', 'error')
    except Exception as e:
        conn.rollback()
        flash('Error deleting file', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

@app.route("/logout")
def logout():
    """Clear session and return to the landing page."""
    session.clear()
    return redirect(url_for("index"))

# Entrypoint for local dev
if __name__ == "__main__":
    # Initialize database if it does not exist
    if not os.path.exists(DB_FILE):
        print("[*] Initializing database...")
        init_db()
    else:
        print("[*] Database already exists, skipping init.")

    # Start Flask application
    app.run(host="0.0.0.0", port=5000, debug=True)
