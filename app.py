from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'
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
@app.route('/user')
def user_dashboard():
    if 'role' in session and session['role'] == 'user':
        return f"Welcome User {session['username']}!"
    else:
        flash('Unauthorized!')
        return redirect(url_for('login'))

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
    app.run(debug=True)