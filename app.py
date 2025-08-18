from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import os
from datetime import datetime
import requests
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'user_photos')
app.config['ATTENDANCE_PHOTO_FOLDER'] = os.path.join('static', 'attendance_photos')
db = SQLAlchemy(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'


@app.route('/')
def home():
    return render_template('home.html')


# Signup route
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Always assign 'user' role for new signups
        role = 'user'
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        user = User.query.filter_by(username=username, role=role).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Logged in successfully!')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials or role!')
            return redirect(url_for('login'))
    # Only show admin option if admin exists, else allow admin login for first user
    admin_exists = User.query.filter_by(role='admin').first() is not None
    return render_template('login.html', admin_existsss=admin_exists)


# Admin dashboard
@app.route('/admin')
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        return f"Welcome Admin {session['username']}!"
    else:
        flash('Unauthorized!')
        return redirect(url_for('login'))

# User dashboard
# User dashboard
@app.route('/user')
def user_dashboard():
    if 'role' in session and session['role'] == 'user':
        return render_template('user_dashboard.html')
    else:
        flash('Unauthorized!')
        return redirect(url_for('login'))

# Upload 3 user photos
@app.route('/user/photos', methods=['GET', 'POST'])
def user_photos():
    if 'role' not in session or session['role'] != 'user':
        flash('Unauthorized!')
        return redirect(url_for('login'))
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
    os.makedirs(user_folder, exist_ok=True)
    photos = []
    for i in range(1, 4):
        photo_path = os.path.join('user_photos', str(session['user_id']), f'photo{i}.jpg')
        if os.path.exists(os.path.join('static', photo_path)):
            photos.append(photo_path.replace('\\', '/'))
    if request.method == 'POST':
        for i in range(1, 4):
            file = request.files.get(f'photo{i}')
            if file:
                filename = f'photo{i}.jpg'
                file.save(os.path.join(user_folder, filename))
        flash('Photos uploaded successfully!')
        return redirect(url_for('user_photos'))
    return render_template('photos.html', photos=photos)

# Attendance marking
@app.route('/user/attendance', methods=['GET', 'POST'])
def user_attendance():
    if 'role' not in session or session['role'] != 'user':
        flash('Unauthorized!')
        return redirect(url_for('login'))
    logs = []
    log_file = f'attendance_{session["user_id"]}.txt'
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = f.readlines()
    if request.method == 'POST':
        action = request.form.get('action')
        file = request.files.get('photo')
        if not file:
            flash('Photo required for attendance!')
            return redirect(url_for('user_attendance'))
        # Save attendance photo
        att_folder = os.path.join(app.config['ATTENDANCE_PHOTO_FOLDER'], str(session['user_id']))
        os.makedirs(att_folder, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        att_photo_path = os.path.join(att_folder, f'{action}_{timestamp}.jpg')
        file.save(att_photo_path)
        # Get public IP and location
        try:
            ip = requests.get('https://api.ipify.org').text
        except:
            ip = 'Unknown'
        try:
            loc_data = requests.get(f'https://ipapi.co/{ip}/json/').json()
            location = f"{loc_data.get('city', '')}, {loc_data.get('region', '')}, {loc_data.get('country_name', '')}"
            latitude = loc_data.get('latitude', '')
            longitude = loc_data.get('longitude', '')
        except:
            location = 'Unknown'
            latitude = ''
            longitude = ''
        # Face verification placeholder (implement with face_recognition library)
        verified = verify_face(session['user_id'], att_photo_path)
        if not verified:
            flash('Face verification failed!')
            return redirect(url_for('user_attendance'))
    log_entry = f"{datetime.now()} - {action.upper()} - IP: {ip} - Location: {location} - Latitude: {latitude} - Longitude: {longitude}\n"
        with open(log_file, 'a') as f:
            f.write(log_entry)
        flash(f'{action.capitalize()} marked!')
        return redirect(url_for('user_attendance'))
    return render_template('attendance.html', logs=logs)

# Breaks
@app.route('/user/break', methods=['GET', 'POST'])
def user_break():
    if 'role' not in session or session['role'] != 'user':
        flash('Unauthorized!')
        return redirect(url_for('login'))
    logs = []
    log_file = f'break_{session["user_id"]}.txt'
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = f.readlines()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'start_break':
            log_entry = f"{datetime.now()} - BREAK STARTED\n"
        elif action == 'end_break':
            log_entry = f"{datetime.now()} - BREAK ENDED\n"
        else:
            log_entry = ''
        if log_entry:
            with open(log_file, 'a') as f:
                f.write(log_entry)
            flash('Break updated!')
        return redirect(url_for('user_break'))
    return render_template('break.html', logs=logs)

# Face verification placeholder
def verify_face(user_id, att_photo_path):
    # TODO: Use face_recognition library to compare attendance photo with user's 3 uploaded photos
    # For now, always return True (simulate success)
    return True

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Ensure only one admin exists, create default admin if none
        if not User.query.filter_by(role='admin').first():
            admin_user = User(username='admin', password=generate_password_hash('admin123'), role='admin')
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True,host='0.0.0.0')