import base64
import json
import ipaddress
import hashlib
import os
import re
import secrets
import sqlite3
import uuid
from html.parser import HTMLParser
from html import escape
from urllib.parse import urlparse
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
ESCROW_EXTENSIONS = {"py", "pyc", "exe", "dll", "bat", "cmd", "ps1", "sh", "php", "js", "html", "htm", "com", "msi"}

app = Flask(__name__, instance_relative_config=True)
app.config.update(
    SECRET_KEY=os.environ.get("NEWDS_SECRET", "dev-only-change-this-secret"),
    DATABASE=os.environ.get("NEWDS_DATABASE", str(Path(app.instance_path) / "newds.sqlite3")),
    UPLOAD_FOLDER=os.environ.get("NEWDS_UPLOADS", str(Path(app.instance_path) / "vault")),
    MAX_CONTENT_LENGTH=2 * MAX_FILE_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("NEWDS_COOKIE_SECURE", "0") == "1",
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
           sort_order INTEGER NOT NULL DEFAULT 0, daily_date TEXT, deleted_at TEXT, note_type TEXT NOT NULL DEFAULT 'note', energy INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
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
        CREATE TABLE IF NOT EXISTS tags (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          name TEXT NOT NULL, normalized_name TEXT NOT NULL, UNIQUE(user_id, normalized_name)
        );
        CREATE TABLE IF NOT EXISTS note_tags (
          note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
          tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
          PRIMARY KEY(note_id, tag_id)
        );
        CREATE INDEX IF NOT EXISTS tags_owner_name ON tags(user_id, normalized_name);
        CREATE TABLE IF NOT EXISTS user_settings (
          user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          reduced_motion INTEGER NOT NULL DEFAULT 0, ambient INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS templates (
          id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          name TEXT NOT NULL, body TEXT NOT NULL, mood TEXT NOT NULL DEFAULT 'lavender', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS secure_snippets (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          label TEXT NOT NULL, salt TEXT NOT NULL, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activity_log (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          action TEXT NOT NULL, object_type TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS activity_owner_time ON activity_log(user_id,created_at DESC);
        """)
        # Lightweight migration for databases created by previous NEWDS builds.
        columns = {row["name"] for row in db.execute("PRAGMA table_info(notes)")}
        for name, definition in (("mood", "TEXT NOT NULL DEFAULT 'lavender'"), ("pinned", "INTEGER NOT NULL DEFAULT 0"), ("sort_order", "INTEGER NOT NULL DEFAULT 0"), ("daily_date", "TEXT"), ("deleted_at", "TEXT"), ("note_type", "TEXT NOT NULL DEFAULT 'note'"), ("energy", "INTEGER")):
            if name not in columns:
                db.execute(f"ALTER TABLE notes ADD COLUMN {name} {definition}")


init_db()


def now_text():
    return datetime.now().isoformat(timespec="seconds")


def safe_local_redirect(fallback):
    target = request.referrer
    if target:
        parsed = urlparse(target)
        if parsed.scheme in {"", "http", "https"} and parsed.netloc in {"", request.host}:
            return target
    return url_for(fallback)


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


def log_activity(action, object_type="vault"):
    if not session.get("user_id"):
        return
    with connect_db() as db:
        db.execute("INSERT INTO activity_log(user_id,action,object_type,created_at) VALUES(?,?,?,?)", (session["user_id"], action[:40], object_type[:40], now_text()))


RICH_TAGS = {"p", "br", "strong", "b", "em", "i", "u", "s", "mark", "h2", "h3", "blockquote", "ul", "ol", "li", "pre", "code", "hr", "a", "input"}
RICH_ATTRS = {"a": {"href", "target", "rel"}, "input": {"type", "checked", "disabled"}}


class RichHTMLSanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self._discard_tags = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self._discard_tags:
            if tag not in {"br", "hr", "input", "img"}:
                self._discard_tags.append(tag)
            return
        if tag in {"script", "style", "iframe", "object", "embed", "template"}:
            self._discard_tags.append(tag)
            return
        if tag not in RICH_TAGS:
            return
        safe = []
        for key, value in attrs:
            key = key.lower()
            if key not in RICH_ATTRS.get(tag, set()):
                continue
            if tag == "a" and key == "href":
                parsed = urlparse(value or "")
                if parsed.scheme not in {"http", "https", "mailto"}:
                    continue
            if tag == "input" and key in {"checked", "disabled"}:
                safe.append(key)
            elif value is not None:
                safe.append(f'{key}="{escape(value, quote=True)}"')
        self.out.append("<" + tag + (" " + " ".join(safe) if safe else "") + ">")

    def handle_startendtag(self, tag, attrs):
        if self._discard_tags:
            return
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._discard_tags:
            if tag in self._discard_tags:
                self._discard_tags.pop()
            return
        if tag in RICH_TAGS and tag not in {"br", "hr", "input"}:
            self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if not self._discard_tags:
            self.out.append(escape(data))


def sanitize_rich_html(value):
    parser = RichHTMLSanitizer()
    parser.feed(value or "")
    return "".join(parser.out).strip()


def rich_text(value):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", value or "")).strip()


def display_rich_html(value):
    value = value or ""
    if "<" not in value:
        return "".join(f"<p>{escape(line)}</p>" for line in value.splitlines() if line.strip()) or "<p></p>"
    return sanitize_rich_html(value)


@app.template_filter("plain_preview")
def plain_preview(value):
    return rich_text(value)[:180]


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def user_note(note_id):
    note = connect_db().execute("SELECT * FROM notes WHERE id=? AND user_id=? AND deleted_at IS NULL", (note_id, session["user_id"])).fetchone()
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


def escrow_key():
    secret = os.environ.get("NEWDS_SECRET", "dev-only-change-this-secret")
    return hashlib.sha256(("newds-escrow-v1:" + secret).encode("utf-8")).digest()


def is_escrow_extension(filename):
    return Path(filename).suffix.lower().lstrip(".") in ESCROW_EXTENSIONS


def escrow_download_name(filename):
    suffix = ".NEWDS"
    return filename if filename.lower().endswith(suffix.lower()) else filename + suffix


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


def note_tags(note_id):
    return connect_db().execute("SELECT t.* FROM tags t JOIN note_tags nt ON nt.tag_id=t.id WHERE nt.note_id=? AND t.user_id=? ORDER BY t.name", (note_id, session["user_id"])).fetchall()


def parse_search(raw):
    terms, filters = [], {}
    for token in raw.split():
        if ":" in token:
            key, value = token.split(":", 1)
            if key in {"is", "mood", "before", "after", "tag"} and value:
                filters.setdefault(key, []).append(value.lower())
                continue
        terms.append(token)
    return " ".join(terms), filters


def sync_tags(db, note_id, raw_tags):
    names = []
    for value in raw_tags.replace(",", " ").split():
        clean = re.sub(r"[^\w-]", "", value.strip().lower())[:32]
        if clean and clean not in names:
            names.append(clean)
    db.execute("DELETE FROM note_tags WHERE note_id=?", (note_id,))
    for name in names[:12]:
        db.execute("INSERT OR IGNORE INTO tags(user_id,name,normalized_name) VALUES(?,?,?)", (session["user_id"], name, name))
        tag = db.execute("SELECT id FROM tags WHERE user_id=? AND normalized_name=?", (session["user_id"], name)).fetchone()
        db.execute("INSERT OR IGNORE INTO note_tags(note_id,tag_id) VALUES(?,?)", (note_id, tag["id"]))


def reminders_for_login(user_id):
    today = date.today()
    db = connect_db()
    notes = db.execute("SELECT id,title,reminder_date FROM notes WHERE user_id=? AND deleted_at IS NULL AND reminder_date IS NOT NULL", (user_id,)).fetchall()
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
        # Serialize the quota check with the insert so concurrent requests
        # cannot create more than the five-account limit.
        db.execute("BEGIN IMMEDIATE")
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
                db.rollback()
                flash("Nama pengguna tersebut sudah digunakan.", "error")
        if db.in_transaction:
            db.rollback()
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
            log_activity("login")
            return redirect(url_for("dashboard"))
        flash("Nama pengguna atau kata sandi tidak cocok.", "error")
    return render_template("auth.html", mode="login")


@app.post("/logout")
@login_required
def logout():
    log_activity("logout")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = connect_db()
    query = request.args.get("q", "").strip()
    text, filters = parse_search(query)
    clauses = ["n.user_id=?", "n.deleted_at IS NULL"]
    params = [session["user_id"]]
    if text:
        like = f"%{text}%"
        clauses.append("(n.title LIKE ? OR (n.encrypted=0 AND n.body LIKE ?) OR EXISTS (SELECT 1 FROM attachments a WHERE a.note_id=n.id AND a.original_name LIKE ?))")
        params.extend([like, like, like])
    for value in filters.get("is", []):
        if value == "encrypted": clauses.append("n.encrypted=1")
        elif value == "pinned": clauses.append("n.pinned=1")
        elif value == "file": clauses.append("EXISTS (SELECT 1 FROM attachments a WHERE a.note_id=n.id)")
    for mood in filters.get("mood", []):
        clauses.append("n.mood=?"); params.append(mood)
    for before in filters.get("before", []):
        clauses.append("substr(n.updated_at,1,10) < ?"); params.append(before)
    for after in filters.get("after", []):
        clauses.append("substr(n.updated_at,1,10) > ?"); params.append(after)
    for tag in filters.get("tag", []):
        clauses.append("EXISTS (SELECT 1 FROM note_tags nt JOIN tags t ON t.id=nt.tag_id WHERE nt.note_id=n.id AND t.user_id=? AND t.normalized_name=?)")
        params.extend([session["user_id"], tag])
    notes = db.execute("SELECT n.* FROM notes n WHERE " + " AND ".join(clauses) + " ORDER BY n.pinned DESC, n.sort_order, n.updated_at DESC", params).fetchall()
    note_data = {row["id"]: note_tags(row["id"]) for row in notes}
    tags = db.execute("SELECT * FROM tags WHERE user_id=? ORDER BY name", (session["user_id"],)).fetchall()
    today = date.today().isoformat()
    daily = db.execute("SELECT * FROM notes WHERE user_id=? AND daily_date=? AND deleted_at IS NULL", (session["user_id"], today)).fetchone()
    active_days = {row[0] for row in db.execute("SELECT DISTINCT substr(created_at,1,10) FROM notes WHERE user_id=? AND deleted_at IS NULL", (session["user_id"],)).fetchall()}
    streak = 0
    cursor = date.today()
    while cursor.isoformat() in active_days:
        streak += 1
        cursor -= timedelta(days=1)
    return render_template("dashboard.html", notes=notes, query=query, search_text=text, filters=filters, tags=tags, note_tags=note_data, reminders=session.pop("login_reminders", []), daily=daily, streak=streak)


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    if request.method == "POST":
        return save_note()
    requested_type = request.args.get("note_type", "note")
    if requested_type in {"journal", "bookmark"}:
        session["new_note_type"] = requested_type
    template_id = request.args.get("template", type=int)
    preset = None
    if template_id:
        preset = connect_db().execute("SELECT * FROM templates WHERE id=? AND (user_id IS NULL OR user_id=?)", (template_id, session["user_id"])).fetchone()
    return render_template("editor.html", note=None, attachments=[], tags=[], preset=preset, note_type=requested_type, unlocked=True, key=None, note_count=connect_db().execute("SELECT COUNT(*) FROM notes WHERE user_id=?", (session["user_id"],)).fetchone()[0])


@app.post("/notes/quick")
@login_required
def quick_note():
    body = rich_text(request.form.get("body", "")).strip()
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
    body = rich_text(request.form.get("body", "")).strip()
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
    return redirect(safe_local_redirect("dashboard"))


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
    note = connect_db().execute("SELECT id FROM notes WHERE user_id=? AND deleted_at IS NULL ORDER BY RANDOM() LIMIT 1", (session["user_id"],)).fetchone()
    if not note:
        flash("Belum ada kenangan untuk diacak—buat catatan pertamamu dulu.", "error")
        return redirect(url_for("dashboard"))
    return redirect(url_for("view_note", note_id=note["id"]))


def save_note(note=None, key=None):
    title = request.form.get("title", "").strip()[:160] or "Catatan tanpa judul"
    body = sanitize_rich_html(request.form.get("body", ""))
    if not rich_text(body):
        body = "<p></p>"
    encrypted = request.form.get("encrypted") == "yes" or bool(note and note["encrypted"])
    password = request.form.get("note_password", "")
    if note and note["encrypted"] and not key:
        abort(403)
    if encrypted and not key:
        if len(password) < 8:
            flash("Kata sandi catatan minimal 8 karakter.", "error")
            return render_template("editor.html", note=note, attachments=attachment_rows(note["id"]) if note else [], tags=note_tags(note["id"]) if note else [], unlocked=True, key=None)
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
    note_type = request.form.get("note_type") or (note["note_type"] if note and "note_type" in note.keys() else session.pop("new_note_type", "note"))
    if note_type not in {"note", "journal", "bookmark"}:
        note_type = "note"
    energy = request.form.get("energy", type=int)
    if energy is not None and not 1 <= energy <= 10:
        energy = None
    db = connect_db()
    timestamp = now_text()
    if note:
        db.execute("UPDATE notes SET title=?,body=?,encrypted=?,salt=?,reminder_date=?,mood=?,daily_date=?,note_type=?,energy=?,updated_at=? WHERE id=? AND user_id=?",
                   (title, stored_body, int(encrypted), base64.urlsafe_b64encode(salt).decode() if encrypted else None, reminder, mood, daily_date, note_type, energy, timestamp, note["id"], session["user_id"]))
        note_id = note["id"]
    else:
        cur = db.execute("INSERT INTO notes(user_id,title,body,encrypted,salt,reminder_date,mood,daily_date,note_type,energy,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                         (session["user_id"], title, stored_body, int(encrypted), base64.urlsafe_b64encode(salt).decode() if encrypted else None, reminder, mood, daily_date, note_type, energy, timestamp, timestamp))
        note_id = cur.lastrowid
    sync_tags(db, note_id, request.form.get("tags", ""))
    db.commit()
    log_activity("note_saved", "note")
    for uploaded in request.files.getlist("files"):
        if not uploaded.filename:
            continue
        original = secure_filename(uploaded.filename) or "attachment"
        ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
        escrowed = ext in ESCROW_EXTENSIONS and not encrypted
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
        elif escrowed:
            nonce, raw = seal(raw, escrow_key())
        stored = uuid.uuid4().hex + (".vault" if encrypted else ".newds" if escrowed else ".blob")
        Path(app.config["UPLOAD_FOLDER"], stored).write_bytes(raw)
        db.execute("INSERT INTO attachments(note_id,user_id,stored_name,original_name,mime_type,size,encrypted,nonce,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                   (note_id, session["user_id"], stored, original, mime, original_size, 1 if encrypted else 2 if escrowed else 0, base64.urlsafe_b64encode(nonce).decode() if nonce else None, now_text()))
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
    return render_template("note.html", note=note, body="", body_html="", unlocked=False, attachments=attachment_rows(note_id))


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
    editable["body"] = display_rich_html(body)
    return render_template("editor.html", note=editable, attachments=attachment_rows(note_id), tags=note_tags(note_id), unlocked=True, key=key, note_count=connect_db().execute("SELECT COUNT(*) FROM notes WHERE user_id=?", (session["user_id"],)).fetchone()[0])


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
    with connect_db() as db:
        db.execute("UPDATE notes SET deleted_at=?,updated_at=? WHERE id=? AND user_id=?", (now_text(), now_text(), note_id, session["user_id"]))
    log_activity("note_trashed", "note")
    session.get("unlocked", {}).pop(str(note_id), None)
    flash("Catatan dipindahkan ke Trash. Kamu masih bisa memulihkannya.", "success")
    return redirect(url_for("dashboard"))


@app.route("/trash")
@login_required
def trash():
    db = connect_db()
    notes = db.execute("SELECT n.*, COUNT(a.id) AS attachment_count FROM notes n LEFT JOIN attachments a ON a.note_id=n.id WHERE n.user_id=? AND n.deleted_at IS NOT NULL GROUP BY n.id ORDER BY n.deleted_at DESC", (session["user_id"],)).fetchall()
    return render_template("trash.html", notes=notes)


@app.post("/trash/<int:note_id>/restore")
@login_required
def restore_note(note_id):
    with connect_db() as db:
        changed = db.execute("UPDATE notes SET deleted_at=NULL,updated_at=? WHERE id=? AND user_id=? AND deleted_at IS NOT NULL", (now_text(), note_id, session["user_id"])).rowcount
    if not changed:
        abort(404)
    log_activity("note_restored", "note")
    flash("Catatan dipulihkan ke vault.", "success")
    return redirect(url_for("trash"))


def permanently_delete(note_id):
    db = connect_db()
    attachments = db.execute("SELECT stored_name FROM attachments WHERE note_id=? AND user_id=?", (note_id, session["user_id"])).fetchall()
    for attachment in attachments:
        Path(app.config["UPLOAD_FOLDER"], attachment["stored_name"]).unlink(missing_ok=True)
    db.execute("DELETE FROM notes WHERE id=? AND user_id=? AND deleted_at IS NOT NULL", (note_id, session["user_id"]))
    db.commit()


@app.post("/trash/<int:note_id>/delete")
@login_required
def permanently_delete_note(note_id):
    permanently_delete(note_id)
    log_activity("note_permanently_deleted", "note")
    flash("Catatan dan lampirannya dihapus permanen.", "success")
    return redirect(url_for("trash"))


@app.post("/trash/empty")
@login_required
def empty_trash():
    ids = connect_db().execute("SELECT id FROM notes WHERE user_id=? AND deleted_at IS NOT NULL", (session["user_id"],)).fetchall()
    for item in ids:
        permanently_delete(item["id"])
    flash("Trash sudah dikosongkan.", "success")
    return redirect(url_for("trash"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    db = connect_db()
    if request.method == "POST":
        with db:
            db.execute("INSERT INTO user_settings(user_id,reduced_motion,ambient,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET reduced_motion=excluded.reduced_motion,ambient=excluded.ambient,updated_at=excluded.updated_at", (session["user_id"], int(request.form.get("reduced_motion") == "yes"), int(request.form.get("ambient") == "yes"), now_text()))
        flash("Preferensi disimpan.", "success")
        return redirect(url_for("settings"))
    preferences = db.execute("SELECT * FROM user_settings WHERE user_id=?", (session["user_id"],)).fetchone()
    user = db.execute("SELECT username,created_at FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("settings.html", preferences=preferences, user=user)


@app.post("/lock")
@login_required
def lock_vault():
    session.clear()
    flash("Vault dikunci. Silakan masuk kembali untuk melanjutkan.", "success")
    return redirect(url_for("login"))


BUILTIN_TEMPLATES = [
    ("Daily Journal", "<h2>Hari ini</h2><p>Apa yang memenuhi pikiranku?</p><p>Apa yang berjalan baik?</p><p>Apa yang ingin kulepaskan?</p><p>Untuk diriku di masa depan:</p>", "rose"),
    ("Brain Dump", "<h2>Yang ada di kepala</h2><ul><li><br></li></ul><h2>Langkah kecil berikutnya</h2><p><br></p>", "lavender"),
    ("Meeting Notes", "<h2>Agenda</h2><ul><li><br></li></ul><h2>Keputusan</h2><p><br></p><h2>Action items</h2><ul><li><input type=\"checkbox\" disabled> </li></ul>", "paper"),
    ("Book Notes", "<h2>Ringkasan</h2><p><br></p><h2>Kutipan favorit</h2><blockquote><br></blockquote><h2>Pikiran</h2><p><br></p>", "midnight"),
    ("Idea Canvas", "<h2>Gagasan</h2><p><br></p><h2>Kenapa menarik?</h2><p><br></p><h2>Eksperimen pertama</h2><p><br></p>", "lavender"),
]


def ensure_builtin_templates(db):
    for name, body, mood in BUILTIN_TEMPLATES:
        db.execute("INSERT INTO templates(user_id,name,body,mood,created_at) SELECT NULL,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM templates WHERE user_id IS NULL AND name=?)", (name, body, mood, now_text(), name))
    db.commit()


@app.route("/journal/new", methods=["GET", "POST"])
@login_required
def new_journal():
    session["new_note_type"] = "journal"
    return redirect(url_for("new_note", note_type="journal"))


@app.route("/journal")
@login_required
def journal_list():
    entries = connect_db().execute("SELECT id,title,mood,energy,encrypted,created_at,updated_at FROM notes WHERE user_id=? AND note_type='journal' AND deleted_at IS NULL ORDER BY created_at DESC", (session["user_id"],)).fetchall()
    return render_template("journal.html", entries=entries)


@app.route("/calendar")
@login_required
def calendar():
    db = connect_db()
    month_text = request.args.get("month", date.today().strftime("%Y-%m"))
    try:
        month = datetime.strptime(month_text, "%Y-%m").date().replace(day=1)
    except ValueError:
        month = date.today().replace(day=1)
    next_month = (month.replace(day=28) + timedelta(days=4)).replace(day=1)
    rows = db.execute("SELECT id,title,created_at,updated_at,daily_date,reminder_date,mood,note_type,encrypted FROM notes WHERE user_id=? AND deleted_at IS NULL AND substr(created_at,1,7)=? ORDER BY created_at DESC", (session["user_id"], month.strftime("%Y-%m"))).fetchall()
    return render_template("calendar.html", month=month, previous=month.replace(day=1)-timedelta(days=1), next_month=next_month, entries=rows)


@app.route("/timeline")
@login_required
def timeline():
    entries = connect_db().execute("SELECT id,title,created_at,updated_at,mood,note_type,encrypted FROM notes WHERE user_id=? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 100", (session["user_id"],)).fetchall()
    return render_template("timeline.html", entries=entries)


@app.route("/on-this-day")
@login_required
def on_this_day():
    today = date.today()
    rows = connect_db().execute("SELECT id,title,created_at,mood,note_type,encrypted FROM notes WHERE user_id=? AND deleted_at IS NULL AND substr(created_at,6,5)=? AND substr(created_at,1,4)<>? ORDER BY created_at DESC", (session["user_id"], today.strftime("%m-%d"), str(today.year))).fetchall()
    return render_template("memory.html", entries=rows, title="On This Day", empty="Belum ada kenangan dari tanggal ini di tahun sebelumnya.")


@app.route("/analytics")
@login_required
def analytics():
    db = connect_db()
    mood_rows = db.execute("SELECT mood,COUNT(*) AS total FROM notes WHERE user_id=? AND deleted_at IS NULL AND note_type='journal' GROUP BY mood ORDER BY total DESC", (session["user_id"],)).fetchall()
    month_rows = db.execute("SELECT substr(created_at,1,7) AS month,COUNT(*) AS total FROM notes WHERE user_id=? AND deleted_at IS NULL GROUP BY month ORDER BY month DESC LIMIT 6", (session["user_id"],)).fetchall()
    total = db.execute("SELECT COUNT(*) FROM notes WHERE user_id=? AND deleted_at IS NULL AND note_type='journal'", (session["user_id"],)).fetchone()[0]
    return render_template("analytics.html", moods=mood_rows, months=month_rows, total=total)


@app.route("/templates")
@login_required
def template_gallery():
    db = connect_db()
    ensure_builtin_templates(db)
    templates = db.execute("SELECT * FROM templates WHERE user_id IS NULL OR user_id=? ORDER BY user_id DESC,name", (session["user_id"],)).fetchall()
    return render_template("templates.html", templates=templates)


@app.post("/templates/save")
@login_required
def save_template():
    name = request.form.get("name", "").strip()[:60]
    body = sanitize_rich_html(request.form.get("body", ""))[:10000]
    if not name or not body:
        abort(400)
    with connect_db() as db:
        db.execute("INSERT INTO templates(user_id,name,body,mood,created_at) VALUES(?,?,?,?,?)", (session["user_id"], name, body, "lavender", now_text()))
    flash("Template pribadi disimpan.", "success")
    return redirect(url_for("template_gallery"))


@app.route("/constellation")
@login_required
def constellation():
    rows = connect_db().execute("SELECT id,title,mood,note_type,encrypted,created_at FROM notes WHERE user_id=? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 100", (session["user_id"],)).fetchall()
    return render_template("constellation.html", entries=rows)


@app.route("/bookmarks")
@login_required
def bookmarks():
    entries = connect_db().execute("SELECT id,title,body,created_at FROM notes WHERE user_id=? AND deleted_at IS NULL AND note_type='bookmark' ORDER BY created_at DESC", (session["user_id"],)).fetchall()
    return render_template("memory.html", entries=entries, title="Bookmarks", empty="Belum ada link yang disimpan.")


@app.post("/bookmarks/capture")
@login_required
def capture_bookmark():
    target = request.form.get("url", "").strip()
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or len(target) > 2048:
        flash("Masukkan URL http atau https yang valid.", "error")
        return redirect(url_for("dashboard"))
    title = request.form.get("title", "").strip()[:160] or parsed.netloc
    timestamp = now_text()
    with connect_db() as db:
        cur = db.execute("INSERT INTO notes(user_id,title,body,note_type,mood,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (session["user_id"], title, f'<p><a href="{escape(target, quote=True)}">{escape(target)}</a></p>', "bookmark", "midnight", timestamp, timestamp))
        sync_tags(db, cur.lastrowid, request.form.get("tags", ""))
    log_activity("bookmark_saved", "bookmark")
    flash("Bookmark tersimpan.", "success")
    return redirect(url_for("bookmarks"))


@app.route("/snippets", methods=["GET", "POST"])
@login_required
def snippets():
    if request.method == "POST":
        label = request.form.get("label", "").strip()[:80]
        secret_value = request.form.get("secret", "")
        password = request.form.get("snippet_password", "")
        if not label or not secret_value or len(password) < 10:
            flash("Isi label, rahasia, dan kata sandi minimal 10 karakter.", "error")
            return redirect(url_for("snippets"))
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        nonce, ciphertext = seal(secret_value.encode(), key)
        with connect_db() as db:
            db.execute("INSERT INTO secure_snippets(user_id,label,salt,nonce,ciphertext,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (session["user_id"], label, base64.urlsafe_b64encode(salt).decode(), base64.urlsafe_b64encode(nonce).decode(), base64.urlsafe_b64encode(ciphertext).decode(), now_text(), now_text()))
        log_activity("snippet_created", "snippet")
        flash("Secure snippet disimpan dalam bentuk terenkripsi.", "success")
        return redirect(url_for("snippets"))
    rows = connect_db().execute("SELECT id,label,created_at,updated_at FROM secure_snippets WHERE user_id=? ORDER BY updated_at DESC", (session["user_id"],)).fetchall()
    return render_template("snippets.html", snippets=rows)


@app.post("/snippets/<int:snippet_id>/reveal")
@login_required
def reveal_snippet(snippet_id):
    item = connect_db().execute("SELECT * FROM secure_snippets WHERE id=? AND user_id=?", (snippet_id, session["user_id"])).fetchone()
    if not item:
        abort(404)
    try:
        password = request.form.get("snippet_password", "")
        key = derive_key(password, base64.urlsafe_b64decode(item["salt"]))
        secret_value = open_sealed(base64.urlsafe_b64decode(item["ciphertext"]), base64.urlsafe_b64decode(item["nonce"]), key).decode()
    except Exception:
        flash("Kata sandi salah atau snippet tidak dapat dibuka.", "error")
        return redirect(url_for("snippets"))
    return render_template("snippet_reveal.html", label=item["label"], secret_value=secret_value)


@app.post("/snippets/<int:snippet_id>/delete")
@login_required
def delete_snippet(snippet_id):
    with connect_db() as db:
        deleted = db.execute("DELETE FROM secure_snippets WHERE id=? AND user_id=?", (snippet_id, session["user_id"])).rowcount
    if not deleted:
        abort(404)
    log_activity("snippet_deleted", "snippet")
    return redirect(url_for("snippets"))


@app.route("/activity")
@login_required
def activity():
    rows = connect_db().execute("SELECT action,object_type,created_at FROM activity_log WHERE user_id=? ORDER BY created_at DESC LIMIT 200", (session["user_id"],)).fetchall()
    return render_template("activity.html", events=rows)


@app.route("/ocr", methods=["GET", "POST"])
@login_required
def ocr():
    abort(404)
    result = None
    error = None
    if request.method == "POST":
        upload = request.files.get("image")
        if not upload or not upload.filename or not (upload.mimetype or "").startswith("image/"):
            error = "Pilih file gambar untuk diproses. Gambar tidak disimpan oleh OCR."
        else:
            try:
                import pytesseract
                from PIL import Image
                from io import BytesIO
                raw = upload.read(MAX_IMAGE_BYTES)
                if len(raw) >= MAX_IMAGE_BYTES:
                    raise ValueError("Image exceeds local OCR size limit")
                result = pytesseract.image_to_string(Image.open(BytesIO(raw)))
                log_activity("local_ocr_processed", "image")
            except ValueError:
                error = "Gambar OCR harus lebih kecil dari 10 MB."
            except ImportError:
                error = "OCR lokal belum tersedia. Pasang Pillow, pytesseract, dan Tesseract OCR lalu coba lagi."
            except Exception:
                error = "Gambar tidak dapat dibaca oleh OCR lokal."
    return render_template("ocr.html", result=result, error=error)


@app.route("/assistant", methods=["GET", "POST"])
@login_required
def local_assistant():
    abort(404)
    answer = None
    error = None
    if request.method == "POST":
        prompt = request.form.get("prompt", "").strip()[:2000]
        endpoint = os.environ.get("NEWDS_LOCAL_AI_URL", "").strip()
        if not endpoint:
            error = "Local AI belum dikonfigurasi. Atur NEWDS_LOCAL_AI_URL ke endpoint model lokal pilihanmu."
        else:
            from urllib.request import Request, urlopen
            try:
                parsed_endpoint = urlparse(endpoint)
                if parsed_endpoint.scheme not in {"http", "https"} or not parsed_endpoint.hostname:
                    raise ValueError("Invalid endpoint")
                host = parsed_endpoint.hostname.lower()
                try:
                    address = ipaddress.ip_address(host)
                    if not address.is_loopback:
                        raise ValueError("Endpoint must be local")
                except ValueError as exc:
                    if str(exc) == "Endpoint must be local":
                        raise
                    if host not in {"localhost"} and not host.endswith(".localhost"):
                        raise ValueError("Endpoint must be local")
                payload = json.dumps({"prompt": prompt}).encode()
                req = Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
                with urlopen(req, timeout=30) as response:
                    answer = json.loads(response.read(1024 * 1024).decode()).get("response", "")
                log_activity("local_assistant_used", "assistant")
            except Exception:
                error = "Tidak dapat menghubungi endpoint AI lokal. Pastikan endpoint berjalan dan menerima JSON {prompt}."
    return render_template("assistant.html", answer=answer, error=error)


@app.post("/attachments/<int:attachment_id>/delete")
@login_required
def delete_attachment(attachment_id):
    db = connect_db()
    item = db.execute("SELECT * FROM attachments WHERE id=? AND user_id=?", (attachment_id, session["user_id"])).fetchone()
    if not item:
        abort(404)
    note = user_note(item["note_id"])
    if note["encrypted"] and not require_unlocked(note):
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
    if note["encrypted"] and not require_unlocked(note):
        abort(403)
    extension_is_escrow = is_escrow_extension(item["original_name"])
    if item["encrypted"] == 2:
        from io import BytesIO
        nonce = base64.urlsafe_b64decode(item["nonce"])
        data = open_sealed(path.read_bytes(), nonce, escrow_key())
        response = send_file(BytesIO(data), mimetype="application/octet-stream", as_attachment=True,
                             download_name=item["original_name"], max_age=0)
    elif item["encrypted"] == 1 and extension_is_escrow:
        nonce = base64.urlsafe_b64decode(item["nonce"])
        original_data = open_sealed(path.read_bytes(), nonce, require_unlocked(note))
        from io import BytesIO
        response = send_file(BytesIO(original_data), mimetype="application/octet-stream",
                             as_attachment=True, download_name=item["original_name"], max_age=0)
    elif item["encrypted"] == 1:
        key = require_unlocked(note)
        if not key:
            abort(403)
        nonce = base64.urlsafe_b64decode(item["nonce"])
        data = open_sealed(path.read_bytes(), nonce, key)
        from io import BytesIO
        response = send_file(BytesIO(data), mimetype=item["mime_type"], as_attachment=request.args.get("download") == "1" or not item["mime_type"].startswith("image/"), download_name=item["original_name"], max_age=0)
    else:
        inline_image = Path(item["original_name"]).suffix.lower().lstrip(".") in IMAGE_EXTENSIONS
        response = send_file(path, mimetype=item["mime_type"] if inline_image else "application/octet-stream", as_attachment=request.args.get("download") == "1" or not inline_image, download_name=item["original_name"], max_age=0)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.errorhandler(413)
def too_large(_error):
    flash("Ukuran total unggahan terlalu besar untuk satu permintaan.", "error")
    return redirect(safe_local_redirect("dashboard"))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
