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

# I collaborated with: John Waweru Muhura

from functools import wraps
from flask import Flask, request, redirect, render_template, session, url_for, flash, send_from_directory, abort, send_file
import sqlite3, os
from datetime import datetime, timedelta, timezone
import uuid
import io
import hashlib
import hmac
import time
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

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

def run_migrations():
    """Ensure required columns exist in existing databases without dropping data."""
    conn = get_db()
    try:
        # Ensure users.otp_secret exists
        cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if 'otp_secret' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN otp_secret BLOB")
        if 'created_at' not in cols:
            # SQLite cannot add a column with a non-constant default in ALTER TABLE
            # so we add the column without default; inserts will set the value explicitly
            try:
                conn.execute("ALTER TABLE users ADD COLUMN created_at DATETIME")
            except sqlite3.OperationalError as e:
                app.logger.warning(f"Migration warning (users.created_at): {e}")

        # Ensure otp_chain.used exists (some older DBs may lack this)
        otp_cols = [row[1] for row in conn.execute("PRAGMA table_info(otp_chain)").fetchall()]
        if otp_cols and 'used' not in otp_cols:
            conn.execute("ALTER TABLE otp_chain ADD COLUMN used BOOLEAN DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError as e:
        # Log and continue; schema.sql creation will handle fresh DBs
        app.logger.warning(f"Migration warning: {e}")
    finally:
        conn.close()

# Ensure database is initialized at import time
os.makedirs(BASE_DIR, exist_ok=True)
init_db()
run_migrations()

# ---------------- OTP Utilities ----------------
def generate_otp_chain(user_id, secret_key, num_otps=1440):
    """
    Generate a chain of OTPs for a user.
    Each OTP is a 6-digit number derived from a hash chain.
    """
    # Start with a random seed
    seed = get_random_bytes(32)
    current_value = seed
    otps = []
    
    # Generate the hash chain in reverse order
    for _ in range(num_otps):
        # Hash the current value with the secret key
        h = hmac.new(secret_key, current_value, hashlib.sha256).digest()
        # Convert to a 6-digit number (last 6 digits of the hash)
        otp = str(int.from_bytes(h, byteorder='big') % 10**6).zfill(6)
        otps.append(otp)
        current_value = h
    
    # Reverse to get the correct order (OTP0, OTP1, ...)
    return otps[::-1]

def get_current_timestamp():
    """Get current timestamp in YYYYMMDDHHMM format."""
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M")

def get_timestamp_minutes_ago(minutes):
    """Get timestamp N minutes ago in YYYYMMDDHHMM format."""
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return dt.strftime("%Y%m%d%H%M")

def verify_otp(user_id, otp, tolerance=2):
    """
    Verify if the provided OTP is valid for the current time window.
    Checks the current minute and ±tolerance minutes.
    """
    current_ts = get_current_timestamp()
    timestamps_to_check = [
        get_timestamp_minutes_ago(i) 
        for i in range(-tolerance, tolerance + 1)
    ]
    
    conn = get_db()
    try:
        # Check if any of the timestamps in the window have this OTP
        placeholders = ','.join(['?'] * len(timestamps_to_check))
        query = f"""
            SELECT id, used FROM otp_chain 
            WHERE user_id = ? 
            AND timestamp IN ({placeholders}) 
            AND otp_code = ?
            AND used = 0
        """
        params = [user_id] + timestamps_to_check + [otp]
        result = conn.execute(query, params).fetchone()
        
        if result and not result['used']:
            # Mark the OTP as used
            conn.execute(
                "UPDATE otp_chain SET used = 1 WHERE id = ?",
                (result['id'],)
            )
            conn.commit()
            return True
        return False
    finally:
        conn.close()

# ---------------- Decorators ----------------
def login_required(f):
    """Decorator to ensure the user is logged in and has completed 2FA."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First, ensure a session exists with a user_id
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.url))

        # Ensure 2FA has been completed; if not, capture next URL and redirect
        if not session.get('verified_2fa'):
            session['next_url'] = request.url
            return redirect(url_for('two_factor'))

        # Validate that the user still exists (e.g., account not deleted)
        user = current_user()
        if not user:
            # Clear invalid session and force re-login
            session.clear()
            return redirect(url_for('login', next=request.url))

        return f(*args, **kwargs)
    return decorated_function

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

# ---------------- Crypto Utilities ----------------
def load_key(key_file="secret_aes.key"):
    """Load the AES-256 key from the provided file path."""
    with open(key_file, "rb") as f:
        return f.read()

def encrypt_file(input_data: bytes, key: bytes) -> bytes:
    """
    Encrypt input_data using AES-256-CBC with PKCS#7 padding.
    Returns IV (16 bytes) prepended to ciphertext.
    """
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(input_data, AES.block_size))
    return iv + ciphertext

def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt data produced by encrypt_file (expects IV||ciphertext).
    """
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    return unpad(plaintext_padded, AES.block_size)

# ---------------- Routes ----------------
@app.route("/")
def index():
    """Landing page with CMU-themed welcome and CTA buttons."""
    return render_template("index.html", title="Information Security Fall 2025 Lab", user=current_user())

def generate_and_store_otps(user_id, secret_key, num_otps=1440):
    """Generate and store OTPs for a user."""
    otps = generate_otp_chain(user_id, secret_key, num_otps)
    
    # Generate timestamps for the next 24 hours (1 per minute)
    now = datetime.now(timezone.utc)
    timestamps = [(now + timedelta(minutes=i)).strftime("%Y%m%d%H%M") for i in range(num_otps)]
    
    # Prepare batch insert
    conn = get_db()
    try:
        conn.executemany(
            "INSERT INTO otp_chain (user_id, timestamp, otp_code) VALUES (?, ?, ?)",
            [(user_id, ts, otp) for ts, otp in zip(timestamps, otps)]
        )
        conn.commit()
    finally:
        conn.close()

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

        conn = None
        try:
            conn = get_db()
            # Start a transaction
            conn.execute("BEGIN")
            
            # Check if user already exists
            existing_user = conn.execute(
                "SELECT id FROM users WHERE andrew_id = ?",
                (andrew_id,)
            ).fetchone()
            
            if existing_user:
                flash("That Andrew ID is already registered.", "error")
                return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
            
            # Hash the password before storing it
            hashed_password = generate_password_hash(password)
            
            # Generate a secure random secret key for this user's OTPs
            secret_key = os.urandom(32)
            
            # Insert the new user with the secret key
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (name, andrew_id, password, otp_secret, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, andrew_id, hashed_password, secret_key, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
            )
            user_id = cursor.lastrowid
            
            # Generate and store OTPs for this user (for 24 hours, one per minute)
            otps = generate_otp_chain(user_id, secret_key, 1440)
            
            # Generate timestamps for the next 24 hours (1 per minute)
            now = datetime.now(timezone.utc)
            timestamps = [(now + timedelta(minutes=i)).strftime("%Y%m%d%H%M") for i in range(1440)]
            
            # Store OTPs in the database
            conn.executemany(
                """
                INSERT INTO otp_chain (user_id, timestamp, otp_code, used)
                VALUES (?, ?, ?, 0)
                """,
                [(user_id, ts, otp) for ts, otp in zip(timestamps, otps)]
            )
            
            # Commit the transaction
            conn.commit()
            
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
            
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("That Andrew ID is already registered.", "error")
            return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error during registration: {str(e)}")
            flash("An error occurred during registration. Please try again.", "error")
            return render_template("register.html", title="Register")
        finally:
            conn.close()
    # GET
    return render_template("register.html", title="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login with Andrew ID and password; then redirect to 2FA."""
    # If user is already logged in and verified, redirect to dashboard
    if current_user() and session.get('verified_2fa'):
        return redirect(url_for('dashboard'))
    
    # Get the next URL from query parameters or default to dashboard
    next_url = request.args.get('next') or url_for('dashboard')
    
    if request.method == "POST":
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE andrew_id = ?", (andrew_id,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            # Store user ID in session for 2FA verification
            session["pending_user_id"] = user["id"]
            session["pending_user_name"] = user["name"]
            # Store the next URL for after 2FA verification
            session["next_url"] = next_url
            # Clear any previous 2FA verification
            session.pop("verified_2fa", None)
            # Close the database connection
            conn.close()
            # Redirect to 2FA verification
            return redirect(url_for("two_factor"))
        else:
            flash("Invalid Andrew ID or password.", "error")
        
        conn.close()
    
    # GET request or failed login
    return render_template("login.html", title="Login", next=next_url)

@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    """Display the 2FA page (GET) and verify the code (POST)."""
    if not session.get("pending_user_id"):
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("2fa.html")

    # POST: verify OTP
    otp = request.form.get("otp", "").strip()
    if not otp or not otp.isdigit() or len(otp) != 6:
        flash("Please enter a valid 6-digit code.", "error")
        return redirect(url_for("two_factor"))

    user_id = session["pending_user_id"]
    conn = get_db()
    try:
        # Verify the OTP with ±2 minutes tolerance
        current_ts = get_current_timestamp()
        timestamps_to_check = [
            current_ts,
            get_timestamp_minutes_ago(1),
            get_timestamp_minutes_ago(2),
            get_timestamp_minutes_ago(-1),
            get_timestamp_minutes_ago(-2),
        ]

        placeholders = ','.join(['?'] * len(timestamps_to_check))
        query = f"""
            SELECT id, used FROM otp_chain 
            WHERE user_id = ? 
            AND timestamp IN ({placeholders}) 
            AND otp_code = ?
            AND used = 0
            LIMIT 1
        """
        params = [user_id] + timestamps_to_check + [otp]
        result = conn.execute(query, params).fetchone()

        if result and not result['used']:
            conn.execute("UPDATE otp_chain SET used = 1 WHERE id = ?", (result['id'],))
            conn.commit()

            session["user_id"] = user_id
            session["user_name"] = session.get("pending_user_name")
            session["verified_2fa"] = True

            next_url = session.pop('next_url', None) or url_for('dashboard')
            session.pop("pending_user_id", None)
            session.pop("pending_user_name", None)

            flash("Login successful!", "success")
            return redirect(next_url)
        else:
            flash("Invalid or expired verification code. Please try again.", "error")
            return redirect(url_for("two_factor"))
    except Exception as e:
        app.logger.error(f"Error during 2FA verification: {str(e)}")
        flash("An error occurred during verification. Please try again.", "error")
        return redirect(url_for("two_factor"))
    finally:
        conn.close()

@app.route("/show-otp")
def show_otp():
    """Show the current and upcoming OTPs for the logged-in user.
    This route is accessible during the 2FA process."""
    # Allow access if either:
    # 1. User is logged in and verified
    # 2. User is in the middle of 2FA (has pending_user_id in session)
    if not current_user() and not session.get('pending_user_id'):
        flash("Please log in first.", "error")
        return redirect(url_for("login", next=url_for("show_otp")))
    
    # Get the user ID - either from the current user or from the pending 2FA session
    user_id = None
    user = current_user()
    if user:
        user_id = user['id']
    elif 'pending_user_id' in session:
        user_id = session['pending_user_id']
    
    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login", next=url_for("show_otp")))
    
    conn = get_db()
    try:
        # Get the current timestamp in the same format as stored in the database
        now = datetime.now(timezone.utc)
        current_ts = now.strftime("%Y%m%d%H%M")
        
        # Get OTPs from 2 minutes back onward (limit 10 rows)
        otps = conn.execute(
            """
            SELECT timestamp, otp_code, used
            FROM otp_chain 
            WHERE user_id = ? AND timestamp >= ?
            ORDER BY timestamp
            LIMIT 10
            """,
            (user_id, get_timestamp_minutes_ago(2))
        ).fetchall()
        
        # If no OTPs found, this might be a new user or OTPs expired
        if not otps:
            flash("No OTPs found. Please contact support.", "error")
            return redirect(url_for("login"))
        
        # Build the otp_list with required fields and statuses
        current_minute_start = now.replace(second=0, microsecond=0)
        tolerance_minutes = 2
        current_time = now.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Helper to format time
        def fmt(dt):
            return dt.strftime("%H:%M:%S %b %d, %Y")

        otp_list = []
        current_index = None
        for idx, row in enumerate(otps):
            otp_time = datetime.strptime(str(row["timestamp"]), "%Y%m%d%H%M").replace(tzinfo=timezone.utc)
            # Determine status
            if otp_time == current_minute_start:
                status = "Current"
                current_index = idx
            else:
                delta_minutes = int((otp_time - current_minute_start).total_seconds() // 60)
                if -tolerance_minutes <= delta_minutes <= tolerance_minutes:
                    status = "Valid"
                elif delta_minutes == 1:
                    status = "Next"  # Will be overridden below if current found
                else:
                    status = "Valid"  # Default label for displayed range

            otp_list.append({
                "time": fmt(otp_time),
                "status": status,
                "code": row["otp_code"],
            })

        # Ensure exactly one "Next" after "Current" if possible
        if current_index is not None and current_index + 1 < len(otp_list):
            # Clear any previous 'Next' and set next minute only
            for i in range(len(otp_list)):
                if i != current_index and otp_list[i]["status"] == "Next":
                    otp_list[i]["status"] = "Valid"
            otp_list[current_index + 1]["status"] = "Next"

        # Find current OTP value (optional banner)
        current_row = conn.execute(
            "SELECT otp_code FROM otp_chain WHERE user_id = ? AND timestamp = ?",
            (user_id, current_ts)
        ).fetchone()
        current_otp = current_row[0] if current_row else None

        return render_template(
            "show_otp.html",
            title="Your OTP Codes",
            otp_list=otp_list,
            current_time=current_time,
            current_otp=current_otp,
        )
    except Exception as e:
        app.logger.error(f"Error in show_otp: {str(e)}")
        flash("An error occurred while retrieving OTPs. Please try again.", "error")
        return redirect(url_for("login"))
    finally:
        conn.close()


@app.route("/dashboard")
@login_required
def dashboard():
    """Dashboard page with file upload form and list of all files."""
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    
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

@app.route("/download/<int:file_id>")
@login_required
def download_file(file_id):
    """Serve uploaded files for download after decryption."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    conn = get_db()
    try:
        # Get file info from database
        file_info = conn.execute(
            "SELECT * FROM files WHERE id = ?", (file_id,)
        ).fetchone()
        
        if not file_info:
            abort(404, "File not found")
            
        file_path = os.path.join(BASE_DIR, 'uploads', file_info['stored_filename'])
        
        # Read the encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            
        # Load the key and decrypt the file
        key = load_key()
        decrypted_data = decrypt_file(encrypted_data, key)
        
        # Create a file-like object from the decrypted data
        file_obj = io.BytesIO(decrypted_data)
        
        # Send the decrypted file
        return send_file(
            file_obj,
            as_attachment=True,
            download_name=file_info['filename'],
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    """Handle file uploads."""
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    
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
        
        # Ensure uploads directory exists
        os.makedirs(os.path.join(BASE_DIR, 'uploads'), exist_ok=True)
        
        # Read file data
        file_data = file.read()
        
        try:
            # Load the key and encrypt the file
            key = load_key()
            encrypted_data = encrypt_file(file_data, key)
            
            # Save the encrypted file
            with open(os.path.join(BASE_DIR, 'uploads', stored_filename), 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            app.logger.error(f"Error encrypting file: {str(e)}")
            flash('Error processing file', 'error')
            return redirect(url_for('dashboard'))
        
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
@login_required
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
    # Clear all session data
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('pending_user_id', None)
    session.pop('pending_user_name', None)
    session.pop('authenticated', None)
    session.clear()
    return redirect(url_for("index"))

# Entrypoint for local dev
if __name__ == "__main__":
    # Initialize database if it does not exist
    if not os.path.exists(DB_FILE):
        print("[*] Initializing database...")
        init_db()
    
    # Ensure the uploads directory exists
    uploads_dir = os.path.join(BASE_DIR, 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)

    # display the key
    key = load_key()
    print("AES Key (hex):", key.hex())
    
    # Run the app
    app.run(debug=True, host="0.0.0.0", port=5000)

    
