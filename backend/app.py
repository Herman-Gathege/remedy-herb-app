from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS if your frontend is running on a different domain

# Configure your database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Change to PostgreSQL URI if using PostgreSQL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Route for user registration (Sign Up)
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    # Check for missing fields
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400

    # Check if user already exists
    user = User.query.filter_by(username=data['username']).first()
    if user:
        return jsonify({'error': 'User already exists'}), 400

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    # Create new user and add to the database
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully!'}), 201

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Check for missing fields
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400

    # Query the user by username
    user = User.query.filter_by(username=data['username']).first()

    # Validate the user and password
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401

    # Create a session for the logged-in user
    session['user_id'] = user.id

    return jsonify({'message': 'Logged in successfully!', 'user': user.username}), 200

# Route for user logout
@app.route('/logout', methods=['POST'])
def logout():
    # Clear the user session
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully!'}), 200

# Protected route (example of user-specific functionality)
@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized access'}), 401

    user = User.query.get(session['user_id'])
    return jsonify({'message': f'Welcome to your dashboard, {user.username}!'}), 200

if __name__ == '__main__':
    app.run(debug=True)
