from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
import psycopg2
import psycopg2.extras
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv
import os

load_dotenv()
DATABASE_URL = os.getenv('DATABASE_URL')
jwt_secret = os.getenv('secret')
key = os.getenv('key')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = key
app.config['JWT_SECRET_KEY'] = jwt_secret
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
app.config['JWT_TOKEN_LOCATION'] = ['headers']

jwt = JWTManager(app)

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


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        return make_response(jsonify({'error': 'Invalid username or password.'}), 401)

    if not user.check_password(password):
        return make_response(jsonify({'error': 'Invalid username or password.'}), 401)

    # return jsonify({'message': 'Login successful.'}), 200
    access_token = create_access_token(identity=user.id, expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES'])

    return jsonify({'access_token': access_token, 'message': 'Login successful.'}), 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    current_user = User.query.filter_by(id=current_user_id).first()
    return jsonify({'message': f'Protected endpoint. Welcome, {current_user.username}!'}), 200


if __name__ == "__main__":
    app.run(debug = True)
