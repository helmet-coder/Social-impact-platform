# === BACKEND (app.py) ===
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
import csv
import io
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'super-secret-key'

# --- Register Route ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect('switchboard.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_pw))
            conn.commit()
            conn.close()
            flash("Registered successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email already registered.", "error")

    return render_template('register.html')

# --- Login Route ---
# --- Login Route ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('switchboard.db')
        c = conn.cursor()
        c.execute("SELECT id, name, password FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            flash("Logged in successfully!", "success")
            return redirect(url_for('homepage'))
        else:
            flash("Invalid email or password", "error")

    return render_template('login.html')

# --- Logout Route ---@app.route('/logout')
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('homepage'))


# --- Function to initialize the database ---
def init_db():
    conn = sqlite3.connect('switchboard.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS switches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT,
                    reason TEXT,
                    alternative TEXT,
                    link TEXT,
                    proof_image TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    email TEXT UNIQUE,
                    password TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    description TEXT,
                    location TEXT,
                    level TEXT,
                    category TEXT,
                    user_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS campaign_joins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER,
                    user_id INTEGER,
                    wants_volunteer INTEGER,
                    show_publicly INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

# --- Route: Home ---
@app.route('/')
def homepage():
    return render_template('home.html')

# --- Start a Campaign ---
@app.route('/start-campaign', methods=['GET', 'POST'])
def start_campaign():
    if 'user_id' not in session:
        flash("Login required.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        level = request.form['level']
        category = request.form['category']
        user_id = session['user_id']

        conn = sqlite3.connect('switchboard.db')
        c = conn.cursor()
        c.execute('''INSERT INTO campaigns (title, description, location, level, category, user_id)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (title, description, location, level, category, user_id))
        conn.commit()
        conn.close()

        flash("Campaign created successfully!", "success")
        return redirect(url_for('campaigns'))

    return render_template('start_campaign.html')

# --- View & Filter Campaigns ---
@app.route('/campaigns')
def campaigns():
    conn = sqlite3.connect('switchboard.db')
    c = conn.cursor()

    # Get filter params
    level = request.args.get('level')
    category = request.args.get('category')

    query = "SELECT c.id, c.title, c.description, c.location, c.level, c.category, u.name FROM campaigns c JOIN users u ON c.user_id = u.id"
    filters = []
    values = []

    if level:
        filters.append("c.level = ?")
        values.append(level)
    if category:
        filters.append("c.category = ?")
        values.append(category)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY c.created_at DESC"
    c.execute(query, values)
    campaigns = c.fetchall()
    conn.close()

    return render_template('campaigns.html', campaigns=campaigns)

# --- Route: Join Campaign ---
@app.route('/join-campaign', methods=['POST'])
def join_campaign():
    if 'user_id' not in session:
        flash("Please log in to join.", "error")
        return redirect(url_for('login'))

    campaign_id = request.form['campaign_id']
    user_id = session['user_id']
    wants_volunteer = 1 if 'wants_volunteer' in request.form else 0
    show_publicly = 1 if 'show_publicly' in request.form else 0

    conn = sqlite3.connect('switchboard.db')
    c = conn.cursor()
    c.execute('INSERT INTO campaign_joins (campaign_id, user_id, wants_volunteer, show_publicly) VALUES (?, ?, ?, ?)',
              (campaign_id, user_id, wants_volunteer, show_publicly))
    conn.commit()
    conn.close()
    flash("Thanks for joining!", "success")
    return redirect(url_for('campaigns'))

# --- Route: Export Supporters (for creator only) ---
@app.route('/export-supporters/<int:campaign_id>')
def export_supporters(campaign_id):
    if 'user_id' not in session:
        flash("Login required.", "error")
        return redirect(url_for('login'))

    conn = sqlite3.connect('switchboard.db')
    c = conn.cursor()
    c.execute('SELECT user_id FROM campaigns WHERE id = ?', (campaign_id,))
    owner = c.fetchone()
    if not owner or owner[0] != session['user_id']:
        conn.close()
        flash("Unauthorized.", "error")
        return redirect(url_for('campaigns'))

    c.execute('''SELECT u.name, u.email, cj.wants_volunteer
                 FROM users u
                 JOIN campaign_joins cj ON u.id = cj.user_id
                 WHERE cj.campaign_id = ?''', (campaign_id,))
    supporters = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Email', 'Wants to Volunteer'])
    for row in supporters:
        writer.writerow(row)

    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()),
                     mimetype='text/csv',
                     download_name='supporters.csv',
                     as_attachment=True)

# --- Page Templates ---
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/repair')
def repair():
    return render_template('repair.html')

# @app.route('/login')
# def login():
#     return render_template('login.html')

# @app.route('/register')
# def register():
#     return render_template('register.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

# --- Context processor ---
@app.context_processor
def inject_user():
    return dict(user_name=session.get('user_name'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

