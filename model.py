from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost/log'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret_key'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


with app.app_context():
    db.create_all()

@app.route('/signup', methods=['POST'])
def signup():
    username = request.json.get('username')
    password = request.json.get('password')


    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400
    
    if not re.match('^[a-zA-Z0-9_]+$', username):
        return jsonify({'error': 'Invalid username. Only letters, digits, and underscores are allowed.'}), 400


    user = User.query.filter_by(username=username).first()

    if user:
        return jsonify({'error': 'Username already exists.'}), 400
    
    if not re.match('^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', password):
        return jsonify({'error': 'Password is too weak. Must contain at least 8 characters, with at least one letter, one digit, and one special character.'}), 400

    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User created successfully.'}), 201

if __name__ == "__main__":
    app.run(debug = True)
