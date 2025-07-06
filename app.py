from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
import csv
import io
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# ✅ Load environment variables from .env
load_dotenv()

DATABASE_PATH = os.getenv('DATABASE_PATH', 'switchboard.db')  # fallback for dev


# ✅ Flask app initialization
app = Flask(__name__)

# ✅ Secure secret key (from environment)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')  # Default fallback only for dev


# ✅ Now, configure it
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ✅ Helper function to check file type
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Register Route ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        try:
            sqlite3.connect(DATABASE_PATH)
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
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        sqlite3.connect(DATABASE_PATH)
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

# --- Logout Route ---
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('homepage'))

# --- Function to initialize the database ---
def init_db():
    sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()

    # Create tables
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
                    title TEXT NOT NULL,
                    description TEXT,
                    location TEXT,
                    level TEXT,
                    category TEXT,
                    latitude REAL,
                    longitude REAL,
                    map_link TEXT,
                    user_id INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    image_path TEXT
                )''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS campaign_joins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id INTEGER,
        user_id INTEGER,
        wants_volunteer INTEGER,
        show_publicly INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (campaign_id, user_id)
    )
''')

    conn.commit()
    conn.close()


# --- Route: Home ---
@app.route('/')
def homepage():
    return render_template('home.html')

@app.route('/campaigns')
def campaigns():
    sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()

    level = request.args.get('level')
    category = request.args.get('category')

    query = '''
    SELECT 
    c.id, c.title, c.description, c.location, c.level, c.category, 
    c.latitude, c.longitude, c.map_link,
    u.name, c.user_id,  
    (SELECT COUNT(*) FROM campaign_joins cj WHERE cj.campaign_id = c.id) as join_count,
    c.image_path
    FROM campaigns c 
    JOIN users u ON c.user_id = u.id
    '''

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
    campaigns_data = c.fetchall()

    campaigns = []
    for campaign in campaigns_data:
        campaign_id = campaign[0]
        c.execute('''SELECT u.name FROM campaign_joins cj 
                     JOIN users u ON cj.user_id = u.id
                     WHERE cj.campaign_id = ? AND cj.show_publicly = 1''', (campaign_id,))
        public_joiners = [row[0] for row in c.fetchall()]

        # ✅ FIXED: This line must be inside the loop
        campaigns.append({
            'id': campaign[0],
            'title': campaign[1],
            'description': campaign[2],
            'location': campaign[3],
            'level': campaign[4],
            'category': campaign[5],
            'latitude': campaign[6],
            'longitude': campaign[7],
            'map_link': campaign[8],
            'creator': campaign[9],
            'creator_id': campaign[10],  # now defined
            'join_count': campaign[11],
            'image_path': campaign[12],
            'public_joiners': public_joiners
        })

    conn.close()
    return render_template('campaigns.html', campaigns=campaigns)

@app.route('/start-campaign', methods=['GET', 'POST'])
@app.route('/create-campaign', methods=['GET', 'POST'])
def create_campaign():
    if 'user_id' not in session:
        flash("Login required to start a campaign.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get form fields
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        level = request.form['level']
        category = request.form['category']
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        map_link = request.form.get('map_link')
        user_id = session['user_id']

        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_path = os.path.join("uploads", filename).replace("\\", "/")
  # Store relative path, e.g. 'static/uploads/filename.jpg'

        sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO campaigns 
                     (title, description, location, level, category, user_id, latitude, longitude, map_link, image_path)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (title, description, location, level, category, user_id, latitude, longitude, map_link, image_path))
        conn.commit()
        conn.close()

        flash("Campaign created successfully!", "success")
        return redirect(url_for('campaigns'))

    return render_template('start_campaign.html')

@app.route('/join-campaign', methods=['POST'])
def join_campaign():
    if 'user_id' not in session:
        flash("Please log in to join.", "error")
        return redirect(url_for('login'))

    campaign_id = request.form.get('campaign_id')
    user_id = session['user_id']
    wants_volunteer = 1 if 'wants_volunteer' in request.form else 0
    show_publicly = 1 if 'show_publicly' in request.form else 0

    try:
        sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()

        # Try insert directly, let UNIQUE constraint handle duplication
        c.execute('''
            INSERT INTO campaign_joins (campaign_id, user_id, wants_volunteer, show_publicly)
            VALUES (?, ?, ?, ?)
        ''', (campaign_id, user_id, wants_volunteer, show_publicly))

        conn.commit()
        flash("Thanks for joining!", "success")

    except sqlite3.IntegrityError:
        # Triggered by UNIQUE constraint (user already joined)
        flash("You've already joined this campaign!", "info")

    finally:
        conn.close()

    return redirect(url_for('campaigns'))

# --- Route: Export Supporters (for creator only) ---
@app.route('/export-supporters/<int:campaign_id>')
def export_supporters(campaign_id):
    if 'user_id' not in session:
        flash("Login required.", "error")
        return redirect(url_for('login'))

    sqlite3.connect(DATABASE_PATH)
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

# --- Add Switch Entry ---
@app.route('/add', methods=['POST'])
def add_switch():
    app_name = request.form['app_name']
    reason = request.form['reason']
    alternative = request.form['alternative']
    link = request.form['link']

    sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO switches (app_name, reason, alternative, link, proof_image) VALUES (?, ?, ?, ?, ?)',
              (app_name, reason, alternative, link, ""))
    conn.commit()
    conn.close()
    flash("Switch added!", "success")
    return redirect(url_for('privacy'))

# --- Informational Pages ---
@app.route('/privacy')
def privacy():
    sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM switches')
    switches = c.fetchall()
    conn.close()
    return render_template('privacy.html', switches=switches)

@app.route('/repair')
def repair():
    return render_template('repair.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("Login required", "error")
        return redirect(url_for('login'))

    user_id = session['user_id']
    sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()

    # Joined Campaigns
    c.execute('''SELECT c.title, c.location, c.category
                 FROM campaigns c
                 JOIN campaign_joins cj ON c.id = cj.campaign_id
                 WHERE cj.user_id = ?''', (user_id,))
    joined_campaigns = c.fetchall()

    # Submitted Switches
    c.execute('''SELECT app_name, alternative
                 FROM switches
                 WHERE proof_image = "" AND id IN (
                     SELECT MAX(id) FROM switches GROUP BY app_name
                 )''')
    switches = c.fetchall()

    conn.close()
    return render_template('profile.html',
                           joined_campaigns=joined_campaigns,
                           switches=switches)

# --- Context processor ---
@app.context_processor
def inject_user():
    return dict(user_name=session.get('user_name'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)