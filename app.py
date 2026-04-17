from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os
from functools import wraps
from dotenv import load_dotenv

load_dotenv(".env")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(32))

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = ""

DB = "portal.db"

# ── Firebase Admin (optional — only if credentials exist) ──────────────────────
_firebase_ready = False
try:
    import firebase_admin, json as _json
    from firebase_admin import credentials, auth as fb_auth

    _sa_json = os.getenv("FIREBASE_SA_JSON", "")   # full JSON string (Render env var)
    _sa_path = os.getenv("FIREBASE_SA_PATH", "")   # local file path (dev)

    if _sa_json:
        cred = credentials.Certificate(_json.loads(_sa_json))
        firebase_admin.initialize_app(cred)
        _firebase_ready = True
        print("[Firebase] Admin SDK ready (from env var)")
    elif _sa_path and os.path.exists(_sa_path):
        cred = credentials.Certificate(_sa_path)
        firebase_admin.initialize_app(cred)
        _firebase_ready = True
        print("[Firebase] Admin SDK ready (from file)")
    else:
        print("[Firebase] No credentials configured — Firebase sync disabled")
except ImportError:
    print("[Firebase] firebase-admin not installed — Firebase sync disabled")


def firebase_create_user(username, password):
    if not _firebase_ready:
        return None
    try:
        user = fb_auth.create_user(email=username, password=password)
        return user.uid
    except Exception as e:
        print(f"[Firebase] create_user failed: {e}")
        return None


def firebase_update_password(firebase_uid, new_password):
    if not _firebase_ready or not firebase_uid:
        return
    try:
        fb_auth.update_user(firebase_uid, password=new_password)
    except Exception as e:
        print(f"[Firebase] update_password failed: {e}")


def firebase_delete_user(firebase_uid):
    if not _firebase_ready or not firebase_uid:
        return
    try:
        fb_auth.delete_user(firebase_uid)
    except Exception as e:
        print(f"[Firebase] delete_user failed: {e}")


# ── Database ───────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                password    TEXT NOT NULL,
                is_admin    INTEGER DEFAULT 0,
                firebase_uid TEXT,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS apps (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                url         TEXT NOT NULL,
                icon        TEXT DEFAULT '🔧',
                description TEXT DEFAULT '',
                is_active   INTEGER DEFAULT 1,
                sort_order  INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS permissions (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                app_id  INTEGER NOT NULL REFERENCES apps(id)  ON DELETE CASCADE,
                PRIMARY KEY (user_id, app_id)
            );
        """)

        # Seed default apps if table is empty
        count = db.execute("SELECT COUNT(*) FROM apps").fetchone()[0]
        if count == 0:
            db.executemany(
                "INSERT INTO apps (name, url, icon, description, sort_order) VALUES (?,?,?,?,?)",
                [
                    ("Stock Signal Analyzer",  "https://stock-signal-analyzer.onrender.com", "📈",
                     "Real-time stock scoring across technical, news, social & analyst signals", 1),
                    ("Self Storage Valuation", "https://self-storage-valuation.web.app",   "🏗️",
                     "Self-storage property appraisal and valuation tool",                    2),
                    ("Data Capture",           "https://data-capture-ssv.web.app",         "📋",
                     "Field data capture and form submission tool",                           3),
                    ("Web Rent Capture",       "http://localhost:8000",                    "🔍",
                     "Self-storage competitor rent scraper and pricing analysis",             4),
                    ("Pokémon Valuation",      "https://pokemon-pricer.web.app",           "🎴",
                     "Pokémon card price lookup and collection valuation",                    5),
                    ("Family Calendar",        "http://localhost:3000",                    "📅",
                     "Shared family calendar with color-coded events per member",             6),
                    ("Appraisal Review",       "http://localhost:8501",                    "📝",
                     "AI-powered PDF appraisal review and rule-based checks",                7),
                ]
            )

        # Seed admin user if no users exist
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            admin_pw = os.getenv("ADMIN_PASSWORD", "admin123")
            db.execute(
                "INSERT INTO users (username, password, is_admin) VALUES (?,?,1)",
                ("admin", generate_password_hash(admin_pw))
            )
            print(f"[Init] Admin user created — username: admin  password: {admin_pw}")


# ── Auth helpers ───────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, row):
        self.id       = row["id"]
        self.username = row["username"]
        self.is_admin = bool(row["is_admin"])
        self.firebase_uid = row["firebase_uid"]


@login_manager.user_loader
def load_user(user_id):
    row = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return User(row) if row else None


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ── Routes: Auth ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user.is_authenticated else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row and check_password_hash(row["password"], password):
            login_user(User(row), remember=True)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ── Routes: Dashboard ─────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    if current_user.is_admin:
        apps = db.execute(
            "SELECT * FROM apps WHERE is_active=1 ORDER BY sort_order, name"
        ).fetchall()
    else:
        apps = db.execute("""
            SELECT a.* FROM apps a
            JOIN permissions p ON p.app_id = a.id
            WHERE p.user_id=? AND a.is_active=1
            ORDER BY a.sort_order, a.name
        """, (current_user.id,)).fetchall()
    return render_template("dashboard.html", apps=apps)


# ── Routes: Admin ─────────────────────────────────────────────────────────────

@app.route("/admin")
@login_required
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY is_admin DESC, username").fetchall()
    apps  = db.execute("SELECT * FROM apps ORDER BY sort_order, name").fetchall()
    perms = {(r["user_id"], r["app_id"]) for r in db.execute("SELECT * FROM permissions").fetchall()}
    return render_template("admin.html", users=users, apps=apps, perms=perms)


@app.route("/admin/user/create", methods=["POST"])
@login_required
@admin_required
def create_user():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "").strip()
    is_admin = 1 if request.form.get("is_admin") else 0

    if not username or not password:
        flash("Username and password are required")
        return redirect(url_for("admin"))

    firebase_uid = firebase_create_user(username, password)

    try:
        get_db().execute(
            "INSERT INTO users (username, password, is_admin, firebase_uid) VALUES (?,?,?,?)",
            (username, generate_password_hash(password), is_admin, firebase_uid)
        )
        flash(f"User '{username}' created" + (" (synced to Firebase)" if firebase_uid else ""))
    except sqlite3.IntegrityError:
        flash(f"Username '{username}' already exists")
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/password", methods=["POST"])
@login_required
@admin_required
def change_password(user_id):
    new_password = request.form.get("password", "").strip()
    if not new_password:
        flash("Password cannot be empty")
        return redirect(url_for("admin"))
    row = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        flash("User not found")
        return redirect(url_for("admin"))
    get_db().execute(
        "UPDATE users SET password=? WHERE id=?",
        (generate_password_hash(new_password), user_id)
    )
    firebase_update_password(row["firebase_uid"], new_password)
    flash(f"Password updated for '{row['username']}'")
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash("You cannot delete yourself")
        return redirect(url_for("admin"))
    row = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if row:
        firebase_delete_user(row["firebase_uid"])
        get_db().execute("DELETE FROM users WHERE id=?", (user_id,))
        flash(f"User '{row['username']}' deleted")
    return redirect(url_for("admin"))


@app.route("/admin/permission", methods=["POST"])
@login_required
@admin_required
def toggle_permission():
    user_id = int(request.form.get("user_id"))
    app_id  = int(request.form.get("app_id"))
    action  = request.form.get("action")  # "grant" or "revoke"
    db = get_db()
    if action == "grant":
        try:
            db.execute("INSERT INTO permissions (user_id, app_id) VALUES (?,?)", (user_id, app_id))
        except sqlite3.IntegrityError:
            pass
    else:
        db.execute("DELETE FROM permissions WHERE user_id=? AND app_id=?", (user_id, app_id))
    return redirect(url_for("admin"))


@app.route("/admin/app/create", methods=["POST"])
@login_required
@admin_required
def create_app():
    name  = request.form.get("name", "").strip()
    url   = request.form.get("url", "").strip()
    icon  = request.form.get("icon", "🔧").strip() or "🔧"
    desc  = request.form.get("description", "").strip()
    if not name or not url:
        flash("Name and URL are required")
        return redirect(url_for("admin"))
    get_db().execute(
        "INSERT INTO apps (name, url, icon, description) VALUES (?,?,?,?)",
        (name, url, icon, desc)
    )
    flash(f"App '{name}' added")
    return redirect(url_for("admin"))


@app.route("/admin/app/<int:app_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_app(app_id):
    row = get_db().execute("SELECT name FROM apps WHERE id=?", (app_id,)).fetchone()
    if row:
        get_db().execute("DELETE FROM apps WHERE id=?", (app_id,))
        flash(f"App '{row['name']}' removed")
    return redirect(url_for("admin"))


# Run on every startup regardless of how the app is launched (gunicorn or direct)
with app.app_context():
    init_db()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5050))
    app.run(debug=os.getenv("FLASK_ENV") != "production", host="0.0.0.0", port=port)
