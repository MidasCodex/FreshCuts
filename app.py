from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # Import Flask-Migrate

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configure your SQLAlchemy database (replace 'sqlite:///mydatabase.db' with your database URL).
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
db = SQLAlchemy(app)

# Initialize Flask-Migrate with your app and db
migrate = Migrate(app, db)

# Secret key for session management (replace with a secure, random key).
app.secret_key = 'your_secret_key'

# Define a User model for the database.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

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
            return redirect(url_for('register'))

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
        if not user:
            flash('Invalid username or password. Please try again.', 'danger')
            return redirect(url_for('login'))

        # Verify the password using the stored hash.
        if check_password_hash(user.password, password):
            # Store the user's ID in the session to track the logged-in user.
            session['user_id'] = user.id
            flash('Login successful.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html')

# Route for user logout.
@app.route('/logout')
def logout():
    # Clear the user's session.
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# ... more routes and functionality ...

if __name__ == "__main__":
    app.run(debug=True)
