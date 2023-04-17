from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
import psycopg2
import psycopg2.extras
from datetime import timedelta
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
    details = db.relationship('UserDetails', backref='user', lazy=True)
    

    def __init__(self, username, password):
        self.username = username
        self.password_hash = generate_password_hash(password)
        

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(80), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(120), nullable=True)

    def __init__(self, user_id, full_name=None, phone_number=None, email=None):
        self.user_id = user_id
        self.full_name = full_name
        self.phone_number = phone_number
        self.email = email

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

    
    access_token = create_access_token(identity=user.id, expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES'])

    return jsonify({'access_token': access_token, 'message': 'Login successful.'}), 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    current_user = User.query.filter_by(id=current_user_id).first()
    user_details = UserDetails.query.filter_by(user_id=current_user_id).first()
    return jsonify(
    {
        "message" : f" Heyyy {current_user.username} !!!",
        "Full name" : f"{user_details.full_name}",
        "Phone Number" : f"{user_details.phone_number}",
        "email" : f"{user_details.email}"
    }

    ), 200


@app.route('/update', methods=['PUT'])
@jwt_required()
def update_username():
    current_user_id = get_jwt_identity()
    current_user = User.query.filter_by(id=current_user_id).first()
    if not current_user:
        return jsonify({'error': 'User not found.'}), 404

    new_username = request.json.get('username')
    if not new_username:
        return jsonify({'error': 'New username is required.'}), 400
    
    user = User.query.filter_by(username=new_username).first()

    if user:
        return jsonify({'error': 'Username already exists.'}), 400
    
    if not re.match('^[a-zA-Z0-9_]+$', new_username):
        return jsonify({'error': 'Invalid username. Only letters, digits, and underscores are allowed.'}), 400

    current_user.username = new_username
    db.session.commit()

    return jsonify({'message': f'Hi {current_user.username} !! Username updated successfully.'}), 200


@app.route('/details', methods=['PUT'])
@jwt_required()
def update_details():
    current_user_id = get_jwt_identity()
    current_user = User.query.filter_by(id=current_user_id).first()
    if not current_user:
        return jsonify({'error': 'User not found.'}), 404
    
    full_name = request.json.get('full_name')
    phone_number = request.json.get('phone_number')
    email = request.json.get('email')

    if not full_name and not phone_number and not email:
        return jsonify({'error': 'At least one detail is required.'}), 400

    details = UserDetails.query.filter_by(user_id=current_user_id).first()

    if not details:
        details = UserDetails(user_id=current_user_id)

    if full_name:
        details.full_name = full_name

    if phone_number:
        details.phone_number = phone_number

    if email:
        details.email = email

    db.session.add(details)
    db.session.commit()

    return jsonify({'message': 'Details updated successfully.'}), 200

if __name__ == "__main__":
    app.run(debug = True)

