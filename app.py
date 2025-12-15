from flask import Flask, render_template, request, redirect, session
from werkzeug.security import check_password_hash
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = "admin_secret_key"

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = "scrypt:32768:8:1$T0zUMyg2n8rOxTKP$0409fb0b4e2a1994ade3a189f2f14aecc625bec1394d7a03e730c14fd2f3be3ecc6299dc2a6e88a78223d10099cd304172585993c5fc41af2a9bde83f405c8ae"

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT,
        message TEXT,
        date TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- ROUTES ----------------

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        category = request.form['category']
        message = request.form['message']
        date = datetime.now().strftime("%d-%m-%Y")

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute(
            "INSERT INTO feedback (category, message, date) VALUES (?, ?, ?)",
            (category, message, date)
        )
        conn.commit()
        conn.close()

        return redirect('/')

    return render_template('feedback.html')


# ----------- ADMIN LOGIN -----------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin'] = True
            return redirect('/admin')
        else:
            error = "Invalid username or password"

    return render_template('admin_login.html', error=error)


# ----------- ADMIN DASHBOARD -----------
@app.route('/admin')
def admin():
    if not session.get('admin'):
        return redirect('/admin-login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM feedback ORDER BY id DESC")
    data = c.fetchall()
    conn.close()

    return render_template('admin.html', data=data)


# ----------- ALL STUDENTS FEEDBACK (NO FILTER) -----------
@app.route('/all-feedback')
def all_feedback():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT category, message, date FROM feedback ORDER BY id DESC")
    data = c.fetchall()
    conn.close()

    return render_template('all_feedback.html', data=data)


# ----------- LOGOUT -----------
@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
