from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
DB_FILE = "vault.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        site_name TEXT NOT NULL,
        site_username TEXT NOT NULL,
        site_password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id))""")
    conn.commit()
    conn.close()

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username aur password dono zaroori hain")
            return redirect(url_for("signup"))
        if len(password) < 6:
            flash("Password kam az kam 6 characters ka hona chahiye")
            return redirect(url_for("signup"))
        password_hash = generate_password_hash(password)
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            conn.close()
            flash("Account ban gaya! Ab login karo.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Ye username pehle se maujood hai")
            return redirect(url_for("signup"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row[1], password):
            session["user_id"] = row[0]
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Username ya password ghalat hai")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, site_name, site_username, site_password FROM passwords WHERE user_id = ?", (session["user_id"],))
    passwords = c.fetchall()
    conn.close()
    return render_template("dashboard.html", passwords=passwords, username=session.get("username"))

@app.route("/add", methods=["POST"])
def add_password():
    if "user_id" not in session:
        return redirect(url_for("login"))
    site_name = request.form.get("site_name", "").strip()
    site_username = request.form.get("site_username", "").strip()
    site_password = request.form.get("site_password", "")
    if site_name and site_username and site_password:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO passwords (user_id, site_name, site_username, site_password) VALUES (?, ?, ?, ?)",
                  (session["user_id"], site_name, site_username, site_password))
        conn.commit()
        conn.close()
        flash("Password save ho gaya")
    return redirect(url_for("dashboard"))

@app.route("/delete/<int:pid>")
def delete_password(pid):
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (pid, session["user_id"]))
    conn.commit()
    conn.close()
    flash("Password delete ho gaya")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
