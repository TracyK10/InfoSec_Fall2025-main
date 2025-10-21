"""
Information Security Fall 2025 Lab 6 - Flask Application
-----------------------------------------------------
Lab 6: Roles, Admin Workflows, and Audit Logging
"""

# I collaborated with: John Waweru Muhura

from functools import wraps
from flask import Flask, request, redirect, render_template, session, url_for, flash, abort, send_file
import sqlite3, os
from datetime import datetime, timedelta, timezone
import uuid
import io
import hashlib
import hmac
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "change-me-in-production")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "infosec_lab.db")

# ---------------- Role Constants ----------------
ROLE_BASIC = "basic"
ROLE_USER_ADMIN = "user_admin"
ROLE_DATA_ADMIN = "data_admin"

# ---------------- Policy Definition ----------------
POLICY = {
    "upload_own_file": ROLE_BASIC,
    "download_own_file": ROLE_BASIC,
    "delete_own_file": ROLE_BASIC,
    "change_password": ROLE_BASIC,
    "create_user": ROLE_USER_ADMIN,
    "delete_user": ROLE_USER_ADMIN,
    "assign_role": ROLE_USER_ADMIN,
    "change_username": ROLE_USER_ADMIN,
    "download_any_file": ROLE_DATA_ADMIN,
    "delete_any_file": ROLE_DATA_ADMIN,
    "upload_any_file": ROLE_DATA_ADMIN,
}

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
        # Ensure users.role exists
        cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if 'role' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'basic'")
        if 'otp_secret' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN otp_secret BLOB")
        if 'created_at' not in cols:
            try:
                conn.execute("ALTER TABLE users ADD COLUMN created_at DATETIME")
            except sqlite3.OperationalError as e:
                app.logger.warning(f"Migration warning (users.created_at): {e}")

        # Ensure files.uploader_id exists
        file_cols = [row[1] for row in conn.execute("PRAGMA table_info(files)").fetchall()]
        if 'uploader_id' not in file_cols:
            conn.execute("ALTER TABLE files ADD COLUMN uploader_id INTEGER")

        # Ensure otp_chain.used exists
        otp_cols = [row[1] for row in conn.execute("PRAGMA table_info(otp_chain)").fetchall()]
        if otp_cols and 'used' not in otp_cols:
            conn.execute("ALTER TABLE otp_chain ADD COLUMN used BOOLEAN DEFAULT 0")
        
        # Migrate audit_logs table to new schema
        audit_cols = [row[1] for row in conn.execute("PRAGMA table_info(audit_logs)").fetchall()]
        if audit_cols:
            # Check if we have the old schema (with 'target' instead of 'target_pretty')
            if 'target' in audit_cols and 'target_pretty' not in audit_cols:
                # Need to recreate the table with new schema
                # 1. Rename old table
                conn.execute("ALTER TABLE audit_logs RENAME TO audit_logs_old")
                
                # 2. Create new table with correct schema
                conn.execute("""
                    CREATE TABLE audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        actor_id INTEGER NOT NULL,
                        actor_andrew_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target_type TEXT,
                        target_id INTEGER,
                        target_pretty TEXT,
                        outcome TEXT NOT NULL,
                        FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
                    )
                """)
                
                # 3. Try to migrate data if old table had compatible columns
                try:
                    conn.execute("""
                        INSERT INTO audit_logs (id, created_at, actor_id, action, target_pretty, outcome)
                        SELECT id, created_at, actor_id, action, target, outcome FROM audit_logs_old
                    """)
                    # Add missing actor_andrew_id from users table
                    conn.execute("""
                        UPDATE audit_logs SET actor_andrew_id = (
                            SELECT andrew_id FROM users WHERE users.id = audit_logs.actor_id
                        )
                        WHERE actor_andrew_id IS NULL OR actor_andrew_id = ''
                    """)
                except sqlite3.OperationalError:
                    # If migration fails, just start fresh
                    pass
                
                # 4. Drop old table
                conn.execute("DROP TABLE audit_logs_old")
            elif 'actor_andrew_id' not in audit_cols:
                # Add missing actor_andrew_id column
                conn.execute("ALTER TABLE audit_logs ADD COLUMN actor_andrew_id TEXT")
                # Populate it from users table
                conn.execute("""
                    UPDATE audit_logs SET actor_andrew_id = (
                        SELECT andrew_id FROM users WHERE users.id = audit_logs.actor_id
                    )
                    WHERE actor_andrew_id IS NULL OR actor_andrew_id = ''
                """)
        
        conn.commit()
    except sqlite3.OperationalError as e:
        app.logger.warning(f"Migration warning: {e}")
    finally:
        conn.close()

# Ensure database is initialized at import time
os.makedirs(BASE_DIR, exist_ok=True)
init_db()
run_migrations()

# ---------------- Audit Logging ----------------
def log_audit(actor_id, action, target, outcome):
    """Log an audit entry."""
    conn = get_db()
    try:
        # Get actor's andrew_id for denormalized storage
        actor = conn.execute("SELECT andrew_id FROM users WHERE id = ?", (actor_id,)).fetchone()
        actor_andrew_id = actor['andrew_id'] if actor else 'unknown'
        
        conn.execute(
            """INSERT INTO audit_logs 
            (actor_id, actor_andrew_id, action, target_pretty, outcome, created_at) 
            VALUES (?, ?, ?, ?, ?, ?)""",
            (actor_id, actor_andrew_id, action, target, outcome, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
    finally:
        conn.close()

# ---------------- Guard Function ----------------
def guard(action, target=None, forbid_self_delete=True):
    """
    Central authorization guard.
    - Requires login + 2FA
    - Checks policy for action
    - Logs all admin actions
    - Blocks self-delete for user_admin
    Returns True if allowed, False if denied.
    """
    # Ensure user is logged in and 2FA verified
    if not session.get('user_id') or not session.get('verified_2fa'):
        return False
    
    user = current_user()
    if not user:
        return False
    
    user_role = user['role']
    user_id = user['id']
    
    # Special case: read_log_file - both admin roles can read logs
    if action == "read_log_file":
        allowed = user_role in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]
        if user_role in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
            outcome = "allowed" if allowed else "denied"
            log_audit(user_id, action, target or "N/A", outcome)
        return allowed
    
    # Check if action is in policy
    if action not in POLICY:
        # Log denied action for admins
        if user_role in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
            log_audit(user_id, action, target or "N/A", "denied")
        return False
    
    required_role = POLICY[action]
    
    # Check role hierarchy
    allowed = False
    if required_role == ROLE_BASIC:
        allowed = True
    elif required_role == ROLE_USER_ADMIN:
        allowed = user_role == ROLE_USER_ADMIN
    elif required_role == ROLE_DATA_ADMIN:
        allowed = user_role == ROLE_DATA_ADMIN
    
    # Special check: forbid self-delete for user_admin
    if action == "delete_user" and forbid_self_delete and user_role == ROLE_USER_ADMIN:
        if target:
            # Target could be user ID or Andrew ID
            try:
                target_id = int(target)
                if target_id == user_id:
                    allowed = False
            except ValueError:
                # Target is Andrew ID
                if target == user['andrew_id']:
                    allowed = False
    
    # Log admin actions
    if user_role in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
        outcome = "allowed" if allowed else "denied"
        log_audit(user_id, action, target or "N/A", outcome)
    
    return allowed

# ---------------- OTP Utilities ----------------
def generate_otp_chain(user_id, secret_key, num_otps=1440):
    """Generate a chain of OTPs for a user."""
    seed = get_random_bytes(32)
    current_value = seed
    otps = []
    
    for _ in range(num_otps):
        h = hmac.new(secret_key, current_value, hashlib.sha256).digest()
        otp = str(int.from_bytes(h, byteorder='big') % 10**6).zfill(6)
        otps.append(otp)
        current_value = h
    
    return otps[::-1]

def get_current_timestamp():
    """Get current timestamp in YYYYMMDDHHMM format."""
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M")

def get_timestamp_minutes_ago(minutes):
    """Get timestamp N minutes ago in YYYYMMDDHHMM format."""
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return dt.strftime("%Y%m%d%H%M")

# ---------------- Decorators ----------------
def login_required(f):
    """Decorator to ensure the user is logged in and has completed 2FA."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.url))

        if not session.get('verified_2fa'):
            session['next_url'] = request.url
            return redirect(url_for('two_factor'))

        user = current_user()
        if not user:
            session.clear()
            return redirect(url_for('login', next=request.url))

        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Decorator to ensure user is an admin (user_admin or data_admin)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = current_user()
        if not user or user['role'] not in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
            flash("Access denied. Admin privileges required.", "error")
            return redirect(url_for('dashboard'))
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
    """Encrypt input_data using AES-256-CBC with PKCS#7 padding."""
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(input_data, AES.block_size))
    return iv + ciphertext

def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt data produced by encrypt_file."""
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

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register: capture name, Andrew ID, and password; redirect to login on success."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not andrew_id or not password:
            flash("All fields are required.", "error")
            return render_template("register.html", title="Register")

        conn = None
        try:
            conn = get_db()
            conn.execute("BEGIN")
            
            existing_user = conn.execute(
                "SELECT id FROM users WHERE andrew_id = ?",
                (andrew_id,)
            ).fetchone()
            
            if existing_user:
                flash("That Andrew ID is already registered.", "error")
                return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
            
            hashed_password = generate_password_hash(password)
            secret_key = os.urandom(32)
            
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (name, andrew_id, password, role, otp_secret, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, andrew_id, hashed_password, ROLE_BASIC, secret_key, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
            )
            user_id = cursor.lastrowid
            
            # Generate OTP chain
            otps = generate_otp_chain(user_id, secret_key, 1440)
            now = datetime.now(timezone.utc)
            timestamps = [(now + timedelta(minutes=i)).strftime("%Y%m%d%H%M") for i in range(1440)]
            
            conn.executemany(
                """
                INSERT INTO otp_chain (user_id, timestamp, otp_code, used)
                VALUES (?, ?, ?, 0)
                """,
                [(user_id, ts, otp) for ts, otp in zip(timestamps, otps)]
            )
            
            conn.commit()
            
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
            
        except sqlite3.IntegrityError:
            if conn:
                conn.rollback()
            flash("That Andrew ID is already registered.", "error")
            return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
        except Exception as e:
            if conn:
                conn.rollback()
            app.logger.error(f"Error during registration: {str(e)}")
            flash("An error occurred during registration. Please try again.", "error")
            return render_template("register.html", title="Register")
        finally:
            if conn:
                conn.close()
    
    return render_template("register.html", title="Register")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login with Andrew ID and password; then redirect to 2FA."""
    if current_user() and session.get('verified_2fa'):
        return redirect(url_for('dashboard'))
    
    next_url = request.args.get('next') or url_for('dashboard')
    
    if request.method == "POST":
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE andrew_id = ?", (andrew_id,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            # IMPORTANT: Ensure valid OTPs before proceeding to 2FA
            ensure_valid_otps(user['id'])
            
            session["pending_user_id"] = user["id"]
            session["pending_user_name"] = user["name"]
            session["next_url"] = next_url
            session.pop("verified_2fa", None)
            conn.close()
            return redirect(url_for("two_factor"))
        else:
            flash("Invalid Andrew ID or password.", "error")
        
        conn.close()
    
    return render_template("login.html", title="Login", next=next_url)

@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    """Display the 2FA page (GET) and verify the code (POST)."""
    if not session.get("pending_user_id"):
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("2fa.html")

    otp = request.form.get("otp", "").strip()
    if not otp or not otp.isdigit() or len(otp) != 6:
        flash("Please enter a valid 6-digit code.", "error")
        return redirect(url_for("two_factor"))

    user_id = session["pending_user_id"]
    conn = get_db()
    try:
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

def ensure_valid_otps(user_id):
    """Ensure user has valid OTPs for the current time and future."""
    conn = get_db()
    try:
        now = datetime.now(timezone.utc)
        current_ts = now.strftime("%Y%m%d%H%M")
        
        # Check if we have valid OTPs for the next hour
        future_ts = (now + timedelta(hours=1)).strftime("%Y%m%d%H%M")
        
        existing_otps = conn.execute(
            """SELECT COUNT(*) as count FROM otp_chain 
               WHERE user_id = ? AND timestamp >= ? AND timestamp <= ?""",
            (user_id, current_ts, future_ts)
        ).fetchone()
        
        # If we have fewer than 60 OTPs for the next hour, regenerate
        if existing_otps['count'] < 60:
            # Get user's OTP secret
            user = conn.execute(
                "SELECT otp_secret FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            
            if not user or not user['otp_secret']:
                return False
            
            # Delete old OTPs
            conn.execute("DELETE FROM otp_chain WHERE user_id = ?", (user_id,))
            
            # Generate new OTPs for next 24 hours
            otps = generate_otp_chain(user_id, user['otp_secret'], 1440)
            timestamps = [(now + timedelta(minutes=i)).strftime("%Y%m%d%H%M") 
                         for i in range(1440)]
            
            conn.executemany(
                """INSERT INTO otp_chain (user_id, timestamp, otp_code, used)
                   VALUES (?, ?, ?, 0)""",
                [(user_id, ts, otp) for ts, otp in zip(timestamps, otps)]
            )
            
            conn.commit()
            return True
        
        return True
        
    except Exception as e:
        app.logger.error(f"Error ensuring valid OTPs: {str(e)}")
        return False
    finally:
        conn.close()

@app.route("/show-otp")
def show_otp():
    """Show the current and upcoming OTPs for the logged-in user."""
    if not current_user() and not session.get('pending_user_id'):
        flash("Please log in first.", "error")
        return redirect(url_for("login", next=url_for("show_otp")))
    
    user_id = None
    user = current_user()
    if user:
        user_id = user['id']
    elif 'pending_user_id' in session:
        user_id = session['pending_user_id']
    
    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login", next=url_for("show_otp")))
    
    # Ensure valid OTPs exist
    ensure_valid_otps(user_id)
    
    conn = get_db()
    try:
        now = datetime.now(timezone.utc)
        current_ts = now.strftime("%Y%m%d%H%M")
        
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
        
        if not otps:
            flash("No OTPs found. Please contact support.", "error")
            return redirect(url_for("login"))
        
        current_minute_start = now.replace(second=0, microsecond=0)
        tolerance_minutes = 2
        current_time = now.strftime("%Y-%m-%d %H:%M:%S UTC")

        def fmt(dt):
            return dt.strftime("%H:%M:%S %b %d, %Y")

        otp_list = []
        current_index = None
        for idx, row in enumerate(otps):
            otp_time = datetime.strptime(str(row["timestamp"]), "%Y%m%d%H%M").replace(tzinfo=timezone.utc)
            if otp_time == current_minute_start:
                status = "Current"
                current_index = idx
            else:
                delta_minutes = int((otp_time - current_minute_start).total_seconds() // 60)
                if -tolerance_minutes <= delta_minutes <= tolerance_minutes:
                    status = "Valid"
                elif delta_minutes == 1:
                    status = "Next"
                else:
                    status = "Valid"

            otp_list.append({
                "time": fmt(otp_time),
                "status": status,
                "code": row["otp_code"],
            })

        if current_index is not None and current_index + 1 < len(otp_list):
            for i in range(len(otp_list)):
                if i != current_index and otp_list[i]["status"] == "Next":
                    otp_list[i]["status"] = "Valid"
            otp_list[current_index + 1]["status"] = "Next"

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
    """Dashboard page - users only see their own files."""
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    
    conn = get_db()
    # Only show files belonging to the current user
    files = conn.execute(
        "SELECT * FROM files WHERE uploader_id = ? ORDER BY upload_timestamp DESC",
        (user['id'],)
    ).fetchall()
    conn.close()
    
    return render_template("dashboard.html", 
                         title="Dashboard", 
                         user=user,
                         current_user=user,
                         files=files)

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    """Handle file uploads - guarded."""
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    
    # Guard check
    if not guard("upload_own_file"):
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))
    
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))
    
    if file:
        original_filename = file.filename
        file_ext = os.path.splitext(original_filename)[1]
        stored_filename = f"{uuid.uuid4().hex}{file_ext}"
        
        os.makedirs(os.path.join(BASE_DIR, 'uploads'), exist_ok=True)
        
        file_data = file.read()
        
        try:
            key = load_key()
            encrypted_data = encrypt_file(file_data, key)
            
            with open(os.path.join(BASE_DIR, 'uploads', stored_filename), 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            app.logger.error(f"Error encrypting file: {str(e)}")
            flash('Error processing file', 'error')
            return redirect(url_for('dashboard'))
        
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO files (filename, stored_filename, uploader_andrew_id, uploader_id) VALUES (?, ?, ?, ?)",
                (original_filename, stored_filename, user['andrew_id'], user['id'])
            )
            conn.commit()
            flash('File uploaded successfully!', 'success')
        except Exception as e:
            flash('Error uploading file', 'error')
        finally:
            conn.close()
    
    return redirect(url_for('dashboard'))

@app.route("/download/<int:file_id>")
@login_required
def download_file(file_id):
    """Download own file - guarded."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    conn = get_db()
    try:
        file_info = conn.execute(
            "SELECT * FROM files WHERE id = ?", (file_id,)
        ).fetchone()
        
        if not file_info:
            abort(404, "File not found")
        
        # Check if file belongs to user
        if file_info['uploader_id'] != user['id']:
            flash("Access denied. You can only download your own files.", "error")
            return redirect(url_for('dashboard'))
        
        # Guard check
        if not guard("download_own_file", file_info['filename']):
            flash("Access denied.", "error")
            return redirect(url_for('dashboard'))
            
        file_path = os.path.join(BASE_DIR, 'uploads', file_info['stored_filename'])
        
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            
        key = load_key()
        decrypted_data = decrypt_file(encrypted_data, key)
        file_obj = io.BytesIO(decrypted_data)
        
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

@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    """Delete own file - guarded."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    conn = get_db()
    try:
        file_info = conn.execute(
            "SELECT * FROM files WHERE id = ?", (file_id,)
        ).fetchone()
        
        if not file_info:
            flash('File not found', 'error')
            return redirect(url_for('dashboard'))
        
        # Check if file belongs to user
        if file_info['uploader_id'] != user['id']:
            flash("Access denied. You can only delete your own files.", "error")
            return redirect(url_for('dashboard'))
        
        # Guard check
        if not guard("delete_own_file", file_info['filename']):
            flash("Access denied.", "error")
            return redirect(url_for('dashboard'))
        
        file_path = os.path.join(BASE_DIR, 'uploads', file_info['stored_filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
        flash('File deleted successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash('Error deleting file', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

# ---------------- Admin Routes ----------------

@app.route("/admin/users")
@login_required
@require_admin
def admin_users():
    """Admin users page - adapts based on role."""
    user = current_user()
    conn = get_db()
    
    users_list = []
    files_list = []
    
    if user['role'] == ROLE_USER_ADMIN:
        # Show user management interface
        users_list = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    elif user['role'] == ROLE_DATA_ADMIN:
        # Show file management interface
        files_list = conn.execute(
            """
            SELECT f.*, u.andrew_id as owner_andrew_id, u.name as owner_name
            FROM files f
            JOIN users u ON f.uploader_id = u.id
            ORDER BY f.upload_timestamp DESC
            """
        ).fetchall()
        # Also get all users for the upload target dropdown
        users_list = conn.execute("SELECT id, andrew_id, name FROM users ORDER BY andrew_id").fetchall()
    
    conn.close()
    
    return render_template(
        "admin_users.html",
        title="Admin - Users",
        user=user,
        users=users_list,
        files=files_list,
        ROLE_BASIC=ROLE_BASIC,
        ROLE_USER_ADMIN=ROLE_USER_ADMIN,
        ROLE_DATA_ADMIN=ROLE_DATA_ADMIN
    )

@app.route("/admin/create-user", methods=["POST"])
@login_required
@require_admin
def admin_create_user():
    """Create a new user - user_admin only."""
    user = current_user()
    
    name = request.form.get("name", "").strip()
    andrew_id = request.form.get("andrew_id", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", ROLE_BASIC)
    
    # Validate role
    if role not in [ROLE_BASIC, ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
        role = ROLE_BASIC
    
    # Guard check
    if not guard("create_user", andrew_id):
        flash("Access denied. Only user admins can create users.", "error")
        return redirect(url_for('admin_users'))
    
    if not name or not andrew_id or not password:
        flash("All fields are required.", "error")
        return redirect(url_for('admin_users'))
    
    conn = get_db()
    try:
        conn.execute("BEGIN")
        
        existing = conn.execute("SELECT id FROM users WHERE andrew_id = ?", (andrew_id,)).fetchone()
        if existing:
            flash("That Andrew ID already exists.", "error")
            return redirect(url_for('admin_users'))
        
        hashed_password = generate_password_hash(password)
        secret_key = os.urandom(32)
        
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (name, andrew_id, password, role, otp_secret, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, andrew_id, hashed_password, role, secret_key, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        )
        new_user_id = cursor.lastrowid
        
        # Generate OTP chain
        otps = generate_otp_chain(new_user_id, secret_key, 1440)
        now = datetime.now(timezone.utc)
        timestamps = [(now + timedelta(minutes=i)).strftime("%Y%m%d%H%M") for i in range(1440)]
        
        conn.executemany(
            "INSERT INTO otp_chain (user_id, timestamp, otp_code, used) VALUES (?, ?, ?, 0)",
            [(new_user_id, ts, otp) for ts, otp in zip(timestamps, otps)]
        )
        
        conn.commit()
        flash(f"User {andrew_id} created successfully with role {role}.", "success")
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error creating user: {str(e)}")
        flash("Error creating user.", "error")
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route("/admin/assign-role", methods=["POST"])
@login_required
@require_admin
def admin_assign_role():
    """Assign role to a user - user_admin only."""
    user_id = request.form.get("user_id")
    new_role = request.form.get("role")
    
    if not user_id or not new_role:
        flash("Invalid request.", "error")
        return redirect(url_for('admin_users'))
    
    if new_role not in [ROLE_BASIC, ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
        flash("Invalid role.", "error")
        return redirect(url_for('admin_users'))
    
    conn = get_db()
    try:
        target_user = conn.execute("SELECT andrew_id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target_user:
            flash("User not found.", "error")
            return redirect(url_for('admin_users'))
        
        target_andrew_id = target_user['andrew_id']
        
        # Guard check
        if not guard("assign_role", target_andrew_id):
            flash("Access denied.", "error")
            return redirect(url_for('admin_users'))
        
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        flash(f"Role updated to {new_role} for {target_andrew_id}.", "success")
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error assigning role: {str(e)}")
        flash("Error assigning role.", "error")
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route("/admin/change-username", methods=["POST"])
@login_required
@require_admin
def admin_change_username():
    """Change a user's name - user_admin only."""
    user_id = request.form.get("user_id")
    new_name = request.form.get("name", "").strip()
    
    if not user_id or not new_name:
        flash("Invalid request.", "error")
        return redirect(url_for('admin_users'))
    
    conn = get_db()
    try:
        target_user = conn.execute("SELECT andrew_id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target_user:
            flash("User not found.", "error")
            return redirect(url_for('admin_users'))
        
        target_andrew_id = target_user['andrew_id']
        
        # Guard check
        if not guard("change_username", target_andrew_id):
            flash("Access denied.", "error")
            return redirect(url_for('admin_users'))
        
        conn.execute("UPDATE users SET name = ? WHERE id = ?", (new_name, user_id))
        conn.commit()
        flash(f"Name updated to '{new_name}' for {target_andrew_id}.", "success")
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error changing username: {str(e)}")
        flash("Error changing username.", "error")
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route("/admin/delete-user", methods=["POST"])
@login_required
@require_admin
def admin_delete_user():
    """Delete a user - user_admin only, cannot delete self."""
    user_id = request.form.get("user_id")
    current = current_user()
    
    if not user_id:
        flash("Invalid request.", "error")
        return redirect(url_for('admin_users'))
    
    conn = get_db()
    try:
        target_user = conn.execute("SELECT andrew_id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target_user:
            flash("User not found.", "error")
            return redirect(url_for('admin_users'))
        
        target_andrew_id = target_user['andrew_id']
        
        # Guard check with self-delete prevention - this will log the attempt
        if not guard("delete_user", target_andrew_id, forbid_self_delete=True):
            flash("Access denied. You cannot delete your own account.", "error")
            return redirect(url_for('admin_users'))
        
        # Delete related records
        conn.execute("DELETE FROM otp_chain WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM files WHERE uploader_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash(f"User {target_andrew_id} deleted successfully.", "success")
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error deleting user: {str(e)}")
        flash("Error deleting user.", "error")
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route("/admin/download/<int:file_id>")
@login_required
@require_admin
def admin_download_file(file_id):
    """Download any file - data_admin only."""
    user = current_user()
    
    conn = get_db()
    try:
        file_info = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        
        if not file_info:
            abort(404, "File not found")
        
        # Guard check
        if not guard("download_any_file", file_info['filename']):
            flash("Access denied. Only data admins can download any file.", "error")
            return redirect(url_for('admin_users'))
        
        file_path = os.path.join(BASE_DIR, 'uploads', file_info['stored_filename'])
        
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        key = load_key()
        decrypted_data = decrypt_file(encrypted_data, key)
        file_obj = io.BytesIO(decrypted_data)
        
        return send_file(
            file_obj,
            as_attachment=True,
            download_name=file_info['filename'],
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('admin_users'))
    finally:
        conn.close()

@app.route("/admin/delete-file/<int:file_id>", methods=["POST"])
@login_required
@require_admin
def admin_delete_file(file_id):
    """Delete any file - data_admin only."""
    user = current_user()
    
    conn = get_db()
    try:
        file_info = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        
        if not file_info:
            flash('File not found', 'error')
            return redirect(url_for('admin_users'))
        
        # Guard check
        if not guard("delete_any_file", file_info['filename']):
            flash("Access denied. Only data admins can delete any file.", "error")
            return redirect(url_for('admin_users'))
        
        file_path = os.path.join(BASE_DIR, 'uploads', file_info['stored_filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
        flash('File deleted successfully!', 'success')
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error deleting file: {str(e)}")
        flash('Error deleting file', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route("/admin/upload", methods=["POST"])
@login_required
@require_admin
def admin_upload_file():
    """Upload file as data_admin - can upload to any user."""
    user = current_user()
    
    # Guard check
    if not guard("upload_any_file"):
        flash("Access denied. Only data admins can upload files.", "error")
        return redirect(url_for('admin_users'))
    
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('admin_users'))
    
    file = request.files['file']
    target_andrew_id = request.form.get('target_user', user['andrew_id'])
    
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('admin_users'))
    
    conn = get_db()
    try:
        # Get target user
        target_user = conn.execute("SELECT id, andrew_id FROM users WHERE andrew_id = ?", (target_andrew_id,)).fetchone()
        if not target_user:
            flash('Target user not found', 'error')
            return redirect(url_for('admin_users'))
        
        original_filename = file.filename
        file_ext = os.path.splitext(original_filename)[1]
        stored_filename = f"{uuid.uuid4().hex}{file_ext}"
        
        os.makedirs(os.path.join(BASE_DIR, 'uploads'), exist_ok=True)
        
        file_data = file.read()
        
        key = load_key()
        encrypted_data = encrypt_file(file_data, key)
        
        with open(os.path.join(BASE_DIR, 'uploads', stored_filename), 'wb') as f:
            f.write(encrypted_data)
        
        conn.execute(
            "INSERT INTO files (filename, stored_filename, uploader_andrew_id, uploader_id) VALUES (?, ?, ?, ?)",
            (original_filename, stored_filename, target_user['andrew_id'], target_user['id'])
        )
        conn.commit()
        flash(f'File uploaded successfully for user {target_andrew_id}!', 'success')
        
    except Exception as e:
        app.logger.error(f"Error uploading file: {str(e)}")
        flash('Error uploading file', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route("/admin/logs")
@login_required
@require_admin
def admin_logs():
    """View audit logs - both admin roles can view."""
    user = current_user()
    
    # Guard check
    if not guard("read_log_file"):
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    try:
        # Use the audit_logs_pretty view as specified in schema.sql
        logs = conn.execute(
            """
            SELECT created_at, actor_andrew_id, action, target_pretty AS target, outcome
            FROM audit_logs_pretty
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()
    finally:
        conn.close()
    
    return render_template("admin_logs.html", title="Audit Logs", user=user, logs=logs)

@app.route("/logout")
def logout():
    """Clear session and return to the landing page."""
    session.clear()
    return redirect(url_for("index"))

# Entrypoint for local dev
if __name__ == "__main__":
    if not os.path.exists(DB_FILE):
        print("[*] Initializing database...")
        init_db()
    
    uploads_dir = os.path.join(BASE_DIR, 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)

    key = load_key()
    print("AES Key (hex):", key.hex())
    
    app.run(debug=True, host="0.0.0.0", port=5000)