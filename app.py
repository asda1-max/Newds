import base64
import os
import re
import secrets
import sqlite3
import uuid
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
MAX_FILE_BYTES = 1024 ** 3
MAX_IMAGE_BYTES = 10 * 1024 ** 2
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
BLOCKED_EXTENSIONS = {"py", "pyc", "exe", "dll", "bat", "cmd", "ps1", "sh", "php", "js", "html", "htm", "com", "msi"}

app = Flask(__name__, instance_relative_config=True)
app.config.update(
    SECRET_KEY=os.environ.get("NEWDS_SECRET", "dev-only-change-this-secret"),
    DATABASE=os.environ.get("NEWDS_DATABASE", str(Path(app.instance_path) / "newds.sqlite3")),
    UPLOAD_FOLDER=os.environ.get("NEWDS_UPLOADS", str(Path(app.instance_path) / "vault")),
    MAX_CONTENT_LENGTH=2 * MAX_FILE_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
Path(app.instance_path).mkdir(parents=True, exist_ok=True)
Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
csrf = CSRFProtect(app)


def connect_db():
    db = sqlite3.connect(app.config["DATABASE"])
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with connect_db() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
          password_hash BLOB NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', encrypted INTEGER NOT NULL DEFAULT 0,
          salt TEXT, reminder_date TEXT, mood TEXT NOT NULL DEFAULT 'lavender', pinned INTEGER NOT NULL DEFAULT 0,
          sort_order INTEGER NOT NULL DEFAULT 0, daily_date TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS attachments (
          id INTEGER PRIMARY KEY, note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          stored_name TEXT NOT NULL UNIQUE, original_name TEXT NOT NULL, mime_type TEXT NOT NULL,
          size INTEGER NOT NULL, encrypted INTEGER NOT NULL DEFAULT 0, nonce TEXT,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reminder_deliveries (
          note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
          milestone INTEGER NOT NULL, delivered_at TEXT NOT NULL, PRIMARY KEY(note_id, milestone)
        );
        CREATE INDEX IF NOT EXISTS notes_owner_updated ON notes(user_id, updated_at DESC);
        """)
        # Lightweight migration for databases created by previous NEWDS builds.
        columns = {row["name"] for row in db.execute("PRAGMA table_info(notes)")}
        for name, definition in (("mood", "TEXT NOT NULL DEFAULT 'lavender'"), ("pinned", "INTEGER NOT NULL DEFAULT 0"), ("sort_order", "INTEGER NOT NULL DEFAULT 0"), ("daily_date", "TEXT")):
            if name not in columns:
                db.execute(f"ALTER TABLE notes ADD COLUMN {name} {definition}")


init_db()


def now_text():
    return datetime.now().isoformat(timespec="seconds")


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def user_note(note_id):
    note = connect_db().execute("SELECT * FROM notes WHERE id=? AND user_id=?", (note_id, session["user_id"])).fetchone()
    if note is None:
        abort(404)
    return note


def derive_key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))


def seal(data, key):
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, data, None)


def open_sealed(data, nonce, key):
    return AESGCM(key).decrypt(nonce, data, None)


def unlocked_key(note):
    token = session.get("unlocked", {}).get(str(note["id"]))
    if not token:
        return None
    return base64.urlsafe_b64decode(token.encode())


def require_unlocked(note):
    key = unlocked_key(note)
    if note["encrypted"] and not key:
        return None
    return key


def attachment_rows(note_id):
    return connect_db().execute("SELECT * FROM attachments WHERE note_id=? AND user_id=? ORDER BY id", (note_id, session["user_id"])).fetchall()


def reminders_for_login(user_id):
    today = date.today()
    db = connect_db()
    notes = db.execute("SELECT id,title,reminder_date FROM notes WHERE user_id=? AND reminder_date IS NOT NULL", (user_id,)).fetchall()
    notices = []
    for note in notes:
        try:
            due = date.fromisoformat(note["reminder_date"])
        except ValueError:
            continue
        delta = (due - today).days
        if delta < 0:
            notices.append({"title": note["title"], "label": f"Terlambat {abs(delta)} hari", "tone": "overdue"})
        elif delta in (1, 2, 3):
            already = db.execute("SELECT 1 FROM reminder_deliveries WHERE note_id=? AND milestone=?", (note["id"], delta)).fetchone()
            if not already:
                db.execute("INSERT INTO reminder_deliveries VALUES(?,?,?)", (note["id"], delta, now_text()))
                notices.append({"title": note["title"], "label": f"{delta} hari lagi", "tone": "soon"})
    db.commit()
    return notices


@app.context_processor
def inject_user():
    return {"username": session.get("username")}


@app.route("/")
def index():
    return redirect(url_for("dashboard" if session.get("user_id") else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = connect_db()
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count >= 5:
            flash("Pendaftaran ditutup: NEWDS saat ini dibatasi untuk lima akun.", "error")
        elif not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            flash("Nama pengguna harus 3–30 karakter (huruf, angka, titik, _ atau -).", "error")
        elif len(password) < 10:
            flash("Gunakan kata sandi minimal 10 karakter.", "error")
        else:
            try:
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                db.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)", (username, hashed, now_text()))
                db.commit()
                flash("Akun berhasil dibuat. Silakan masuk.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Nama pengguna tersebut sudah digunakan.", "error")
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = connect_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["unlocked"] = {}
            session["login_reminders"] = reminders_for_login(user["id"])
            return redirect(url_for("dashboard"))
        flash("Nama pengguna atau kata sandi tidak cocok.", "error")
    return render_template("auth.html", mode="login")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = connect_db()
    query = request.args.get("q", "").strip()
    if query:
        notes = db.execute("SELECT * FROM notes WHERE user_id=? AND (title LIKE ? OR (encrypted=0 AND body LIKE ?)) ORDER BY pinned DESC, sort_order, updated_at DESC",
                           (session["user_id"], f"%{query}%", f"%{query}%")).fetchall()
    else:
        notes = db.execute("SELECT * FROM notes WHERE user_id=? ORDER BY pinned DESC, sort_order, updated_at DESC", (session["user_id"],)).fetchall()
    today = date.today().isoformat()
    daily = db.execute("SELECT * FROM notes WHERE user_id=? AND daily_date=?", (session["user_id"], today)).fetchone()
    active_days = {row[0] for row in db.execute("SELECT DISTINCT substr(created_at,1,10) FROM notes WHERE user_id=?", (session["user_id"],)).fetchall()}
    streak = 0
    cursor = date.today()
    while cursor.isoformat() in active_days:
        streak += 1
        cursor -= timedelta(days=1)
    return render_template("dashboard.html", notes=notes, query=query, reminders=session.pop("login_reminders", []), daily=daily, streak=streak)


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    if request.method == "POST":
        return save_note()
    return render_template("editor.html", note=None, attachments=[], unlocked=True, key=None, note_count=connect_db().execute("SELECT COUNT(*) FROM notes WHERE user_id=?", (session["user_id"],)).fetchone()[0])


@app.post("/notes/quick")
@login_required
def quick_note():
    body = request.form.get("body", "").strip()
    if not body:
        flash("Tulis sedikit dulu, Darling.", "error")
        return redirect(url_for("dashboard"))
    timestamp = now_text()
    title = request.form.get("title", "").strip()[:160] or body.splitlines()[0][:70]
    with connect_db() as db:
        db.execute("INSERT INTO notes(user_id,title,body,mood,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                   (session["user_id"], title, body, "lavender", timestamp, timestamp))
    flash("Ide kecil berhasil disimpan.", "success")
    return redirect(url_for("dashboard"))


@app.post("/notes/daily")
@login_required
def daily_thought():
    body = request.form.get("body", "").strip()
    if not body:
        return redirect(url_for("dashboard"))
    today = date.today().isoformat()
    timestamp = now_text()
    with connect_db() as db:
        existing = db.execute("SELECT id FROM notes WHERE user_id=? AND daily_date=?", (session["user_id"], today)).fetchone()
        if existing:
            db.execute("UPDATE notes SET body=?,updated_at=? WHERE id=?", (body, timestamp, existing["id"]))
        else:
            db.execute("INSERT INTO notes(user_id,title,body,mood,daily_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                       (session["user_id"], "Daily thought", body, "rose", today, timestamp, timestamp))
    return redirect(url_for("dashboard"))


@app.post("/notes/<int:note_id>/pin")
@login_required
def toggle_pin(note_id):
    note = user_note(note_id)
    with connect_db() as db:
        db.execute("UPDATE notes SET pinned=? WHERE id=? AND user_id=?", (0 if note["pinned"] else 1, note_id, session["user_id"]))
    return redirect(request.referrer or url_for("dashboard"))


@app.post("/notes/reorder")
@login_required
def reorder_notes():
    ids = request.form.getlist("note_ids[]")
    with connect_db() as db:
        for position, note_id in enumerate(ids):
            if note_id.isdigit():
                db.execute("UPDATE notes SET sort_order=? WHERE id=? AND user_id=?", (position, int(note_id), session["user_id"]))
    return ("", 204)


@app.route("/notes/random")
@login_required
def random_note():
    note = connect_db().execute("SELECT id FROM notes WHERE user_id=? ORDER BY RANDOM() LIMIT 1", (session["user_id"],)).fetchone()
    if not note:
        flash("Belum ada kenangan untuk diacak—buat catatan pertamamu dulu.", "error")
        return redirect(url_for("dashboard"))
    return redirect(url_for("view_note", note_id=note["id"]))


def save_note(note=None, key=None):
    title = request.form.get("title", "").strip()[:160] or "Catatan tanpa judul"
    body = request.form.get("body", "")
    encrypted = request.form.get("encrypted") == "yes" or bool(note and note["encrypted"])
    password = request.form.get("note_password", "")
    if note and note["encrypted"] and not key:
        abort(403)
    if encrypted and not key:
        if len(password) < 8:
            flash("Kata sandi catatan minimal 8 karakter.", "error")
            return render_template("editor.html", note=note, attachments=attachment_rows(note["id"]) if note else [], unlocked=True, key=None)
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
    else:
        salt = base64.urlsafe_b64decode(note["salt"]) if note and note["salt"] else None
    stored_body = body
    if encrypted:
        nonce, cipher = seal(body.encode(), key)
        stored_body = "enc:" + base64.urlsafe_b64encode(nonce + cipher).decode()
    reminder = request.form.get("reminder_date") or None
    mood = request.form.get("mood", note["mood"] if note and "mood" in note.keys() else "lavender")
    if mood not in {"lavender", "rose", "midnight", "paper"}:
        mood = "lavender"
    daily_date = date.today().isoformat() if request.form.get("daily_thought") == "yes" else (note["daily_date"] if note and "daily_date" in note.keys() else None)
    db = connect_db()
    timestamp = now_text()
    if note:
        db.execute("UPDATE notes SET title=?,body=?,encrypted=?,salt=?,reminder_date=?,mood=?,daily_date=?,updated_at=? WHERE id=? AND user_id=?",
                   (title, stored_body, int(encrypted), base64.urlsafe_b64encode(salt).decode() if encrypted else None, reminder, mood, daily_date, timestamp, note["id"], session["user_id"]))
        note_id = note["id"]
    else:
        cur = db.execute("INSERT INTO notes(user_id,title,body,encrypted,salt,reminder_date,mood,daily_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (session["user_id"], title, stored_body, int(encrypted), base64.urlsafe_b64encode(salt).decode() if encrypted else None, reminder, mood, daily_date, timestamp, timestamp))
        note_id = cur.lastrowid
    db.commit()
    for uploaded in request.files.getlist("files"):
        if not uploaded.filename:
            continue
        original = secure_filename(uploaded.filename) or "attachment"
        ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
        if ext in BLOCKED_EXTENSIONS:
            flash(f"Tipe berkas {ext} tidak diizinkan.", "error")
            continue
        raw = uploaded.read(MAX_FILE_BYTES + 1)
        if len(raw) >= MAX_FILE_BYTES:
            flash(f"{original}: berkas harus lebih kecil dari 1 GB.", "error")
            continue
        mime = uploaded.mimetype or "application/octet-stream"
        is_image = mime.startswith("image/") or ext in IMAGE_EXTENSIONS
        if is_image and len(raw) >= MAX_IMAGE_BYTES:
            flash(f"{original}: gambar harus lebih kecil dari 10 MB.", "error")
            continue
        original_size = len(raw)
        nonce = None
        if encrypted:
            nonce, raw = seal(raw, key)
        stored = uuid.uuid4().hex + (".vault" if encrypted else ".blob")
        Path(app.config["UPLOAD_FOLDER"], stored).write_bytes(raw)
        db.execute("INSERT INTO attachments(note_id,user_id,stored_name,original_name,mime_type,size,encrypted,nonce,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                   (note_id, session["user_id"], stored, original, mime, original_size, int(encrypted), base64.urlsafe_b64encode(nonce).decode() if nonce else None, now_text()))
    db.commit()
    if encrypted:
        unlocked = session.get("unlocked", {})
        unlocked[str(note_id)] = base64.urlsafe_b64encode(key).decode()
        session["unlocked"] = unlocked
    if note:
        # Reminder milestones belong to the current due date only.
        previous = note["reminder_date"]
        if previous != reminder:
            db.execute("DELETE FROM reminder_deliveries WHERE note_id=?", (note_id,))
            db.commit()
    flash("Catatan tersimpan dengan aman.", "success")
    return redirect(url_for("view_note", note_id=note_id))


@app.route("/notes/<int:note_id>", methods=["GET", "POST"])
@login_required
def view_note(note_id):
    note = user_note(note_id)
    if not note["encrypted"]:
        return redirect(url_for("edit_note", note_id=note_id))
    if note["encrypted"] and request.method == "POST" and request.form.get("action") == "unlock":
        try:
            salt = base64.urlsafe_b64decode(note["salt"])
            key = derive_key(request.form.get("note_password", ""), salt)
            token = note["body"][4:]
            blob = base64.urlsafe_b64decode(token)
            open_sealed(blob[12:], blob[:12], key)
            unlocked = session.get("unlocked", {})
            unlocked[str(note_id)] = base64.urlsafe_b64encode(key).decode()
            session["unlocked"] = unlocked
            return redirect(url_for("edit_note", note_id=note_id))
        except Exception:
            flash("Kata sandi salah atau data tidak dapat dibuka.", "error")
    key = require_unlocked(note)
    if note["encrypted"] and key:
        return redirect(url_for("edit_note", note_id=note_id))
    return render_template("note.html", note=note, body="", unlocked=False, attachments=attachment_rows(note_id))


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):
    note = user_note(note_id)
    key = require_unlocked(note)
    if note["encrypted"] and not key:
        flash("Buka kunci catatan sebelum mengeditnya.", "error")
        return redirect(url_for("view_note", note_id=note_id))
    if request.method == "POST":
        return save_note(note, key)
    body = note["body"]
    if note["encrypted"]:
        blob = base64.urlsafe_b64decode(body[4:])
        body = open_sealed(blob[12:], blob[:12], key).decode()
    editable = dict(note)
    editable["body"] = body
    return render_template("editor.html", note=editable, attachments=attachment_rows(note_id), unlocked=True, key=key, note_count=connect_db().execute("SELECT COUNT(*) FROM notes WHERE user_id=?", (session["user_id"],)).fetchone()[0])


@app.post("/notes/<int:note_id>/mood")
@login_required
def update_mood(note_id):
    user_note(note_id)
    mood = request.form.get("mood", "lavender")
    if mood not in {"lavender", "rose", "midnight", "paper"}:
        abort(400)
    with connect_db() as db:
        db.execute("UPDATE notes SET mood=?,updated_at=? WHERE id=? AND user_id=?", (mood, now_text(), note_id, session["user_id"]))
    return redirect(url_for("view_note", note_id=note_id))


@app.post("/notes/<int:note_id>/delete")
@login_required
def delete_note(note_id):
    note = user_note(note_id)
    for attachment in attachment_rows(note_id):
        try:
            Path(app.config["UPLOAD_FOLDER"], attachment["stored_name"]).unlink(missing_ok=True)
        except OSError:
            pass
    with connect_db() as db:
        db.execute("DELETE FROM notes WHERE id=? AND user_id=?", (note_id, session["user_id"]))
    session.get("unlocked", {}).pop(str(note_id), None)
    flash("Catatan dihapus.", "success")
    return redirect(url_for("dashboard"))


@app.post("/attachments/<int:attachment_id>/delete")
@login_required
def delete_attachment(attachment_id):
    db = connect_db()
    item = db.execute("SELECT * FROM attachments WHERE id=? AND user_id=?", (attachment_id, session["user_id"])).fetchone()
    if not item:
        abort(404)
    note = user_note(item["note_id"])
    if item["encrypted"] and not require_unlocked(note):
        abort(403)
    Path(app.config["UPLOAD_FOLDER"], item["stored_name"]).unlink(missing_ok=True)
    db.execute("DELETE FROM attachments WHERE id=?", (attachment_id,))
    db.commit()
    return redirect(url_for("edit_note", note_id=item["note_id"]))


@app.route("/attachments/<int:attachment_id>")
@login_required
def get_attachment(attachment_id):
    db = connect_db()
    item = db.execute("SELECT * FROM attachments WHERE id=? AND user_id=?", (attachment_id, session["user_id"])).fetchone()
    if not item:
        abort(404)
    note = user_note(item["note_id"])
    path = Path(app.config["UPLOAD_FOLDER"], item["stored_name"])
    if item["encrypted"]:
        key = require_unlocked(note)
        if not key:
            abort(403)
        nonce = base64.urlsafe_b64decode(item["nonce"])
        data = open_sealed(path.read_bytes(), nonce, key)
        from io import BytesIO
        return send_file(BytesIO(data), mimetype=item["mime_type"], as_attachment=request.args.get("download") == "1" or not item["mime_type"].startswith("image/"), download_name=item["original_name"], max_age=0)
    return send_file(path, mimetype=item["mime_type"], as_attachment=request.args.get("download") == "1" or not item["mime_type"].startswith("image/"), download_name=item["original_name"], max_age=0)


@app.errorhandler(413)
def too_large(_error):
    flash("Ukuran total unggahan terlalu besar untuk satu permintaan.", "error")
    return redirect(request.referrer or url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
