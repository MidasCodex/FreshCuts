# app.py

import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configure SQLAlchemy database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
db = SQLAlchemy(app)

# Initialize Flask-Migrate with app and db
migrate = Migrate(app, db)

# Secret key for session management (replace with a secure, random key).
app.secret_key = secrets.token_hex(16)  # Generate a secure secret key


# Define a User model for the database.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


# Define an Admin model for the database.
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


# Create the database tables within the application context.
with app.app_context():
    db.create_all()


# Route for user registration.
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists in the database.
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            # Hash the user's password for security.
            hashed_password = generate_password_hash(password, method='sha256')

            # Create a new user and add it to the database.
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


# Route for user login.
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username exists in the database.
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Store the user's ID in the session to track the logged-in user.
            session['user_id'] = user.id
            flash('Login successful.', 'success')
            return redirect(url_for('home'))

        flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html')


# Route for homepage.
@app.route('/home')
def home():
    return render_template('home.html')


# Route for aboutpage.
@app.route('/about')
def about():
    return render_template('about.html')


# Route for faq.
@app.route('/faq')
def faq():
    return render_template('faq.html')


# Route for faq.
@app.route('/tos')
def tos():
    return render_template('tos.html')


# Route for user logout.
@app.route('/logout')
def logout():
    # Clear the user's session.
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# Route for the root URL ("/") to display the "App Running" message.
@app.route('/')
def app_running():
    return render_template('app_running.html')


# Admin registration route.
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists in the database.
        existing_admin = Admin.query.filter_by(username=username).first()
        if existing_admin:
            flash('Admin username already exists. Please choose a different one.', 'danger')
        else:
            # Hash the admin's password for security.
            hashed_password = generate_password_hash(password, method='sha256')

            # Create a new admin and add it to the database.
            new_admin = Admin(username=username, password=hashed_password, is_admin=True)
            db.session.add(new_admin)
            db.session.commit()

            flash('Admin registration successful. You can now log in as an admin.', 'success')
            return redirect(url_for('admin_login'))

    return render_template('admin_register.html')


# Admin login route.
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username exists in the database.
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            if admin.is_admin:
                session['admin_id'] = admin.id
                flash('Admin login successful.', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('You do not have permission to log in as an admin.', 'danger')
        else:
            flash('Invalid admin username or password. Please try again.', 'danger')

    return render_template('admin_login.html')


# Admin dashboard route.
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' in session:
        # Fetch all users from the database
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)
    else:
        flash('You need to log in as an admin to access the admin dashboard.', 'danger')
        return redirect(url_for('admin_login'))


# Example for the view_user route
@app.route('/admin/user/<int:user_id>/view')
def view_user(user_id):
    user = User.query.get(user_id)
    if user:
        return render_template('view_user.html', user=user)
    else:
        abort(404)


# Example for the edit_user route
@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get(user_id)
    if user:
        if request.method == 'POST':
            # Update user details in the database
            user.username = request.form['username']
            db.session.commit()
            flash('User details updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('edit_user.html', user=user)
    else:
        abort(404)


# Example for the delete_user route
@app.route('/admin/user/<int:user_id>/delete', methods=['GET', 'POST'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        if request.method == 'POST':
            # Delete user from the database
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('delete_user.html', user=user)
    else:
        abort(404)


if __name__ == "__main__":
    app.run(debug=True)
