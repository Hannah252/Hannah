from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
import psycopg2
import psycopg2.extras
from datetime import timedelta
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_current_user
from dotenv import load_dotenv
import os


load_dotenv()
D_URL = os.getenv('D_URL')
jwt_secret = os.getenv('secret')
key = os.getenv('key')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = D_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = key
app.config['JWT_SECRET_KEY'] = jwt_secret
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)
app.config['JWT_TOKEN_LOCATION'] = ['headers']

jwt = JWTManager(app)

db = SQLAlchemy(app)


ROLES = {'admin': 0, 'manager': 1, 'employee': 2}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.Integer, nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    details = db.relationship('UserDetails', backref='user', lazy=True, uselist=False)

    def __init__(self, username, password, role, manager_id=None):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.role = role
        self.manager_id = manager_id

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
def get_key(val):
    for key, value in ROLES.items():
        if val == value:
            return key



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

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', password='password', role=ROLES['admin'])
        db.session.add(admin)
        db.session.commit()

def get_current_user():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    return user

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()
    if not user:
        return make_response(jsonify({'error': 'Invalid username or password.'}), 401)

    if not user.check_password(password):
        return make_response(jsonify({'error': 'Invalid username or password.'}), 401)
    access_token = create_access_token(identity=user.id, additional_claims={'role': user.role})
    return jsonify({'access_token': access_token, 'message':'Login Successful'}), 200

@app.route('/user', methods=['POST'])
@jwt_required()
def user():
    current_user = get_current_user()
    if current_user.role != ROLES['admin']:
        return jsonify({'message': 'Unauthorized access'}), 403
    username = request.json.get('username')
    password = request.json.get('password')
    role = request.json.get('role')
    manager_id = request.json.get('manager_id')
    if not username:
        return jsonify({'message': 'Username is required'}), 400
    if not password:
        return jsonify({'message': 'Password is required'}), 400
    if not role:
        return jsonify({'message': 'Role is required'}), 400
    if role not in ROLES.keys():
        return jsonify({'message': 'Invalid role'}), 400
    if manager_id:
        m_id = manager_id
        manager=User.query.filter_by(id=m_id).first()
        if manager.role != ROLES['manager']:
            return jsonify({'message':'The manager id is not found'}),404

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Username already taken'}), 400

    user = User(username=username, password=password, role=ROLES[role], manager_id=manager_id)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201


@app.route('/manager/<int:user_id>', methods=['PATCH'])
@jwt_required()
def assign_manager(user_id):
    current_user = get_current_user()
    if current_user.role != ROLES['admin']:
        return jsonify({'message':'Unauthorized Access'}),403
    
    user = User.query.filter_by(id=user_id).first()
    if user:
        user.manager_id = request.json.get('manager_id')
        if not user.manager_id:
            return jsonify({'message':'manager id not found'}),404
        m_id = user.manager_id
        manager=User.query.filter_by(id=m_id).first()
        if manager.role != ROLES['manager']:
            return jsonify({'message':'The manager id is not found'}),404
        db.session.commit()
       
        return jsonify({'message':'Manager assigned successfully'})
    else:
        return jsonify({'message':'employee not found'}),404

@app.route('/details', methods=['POST'])
@jwt_required()
def report():
    
    current_user = get_current_user()
    if current_user.role != ROLES['admin'] and current_user.role != ROLES['manager']:
        return jsonify({'message': 'Unauthorized access'}), 403
    
    user_id = request.json.get('user_id')
    full_name = request.json.get('full_name')
    phone_number = request.json.get('phone_number')
    email = request.json.get('email')  
    

    if not user_id:
        return jsonify({'message' : 'User id required'}), 400
    
    if not full_name and not phone_number and not email:
        return jsonify({'error': 'At least one detail is required.'}), 400

         
    details = UserDetails(user_id=user_id,full_name=full_name, phone_number=phone_number, email=email)

    db.session.add(details)
    db.session.commit()

    return jsonify({'message': 'Details updated successfully.'}), 200


@app.route('/display', methods=['GET'])
@jwt_required()
def display_details():
    current_user=get_current_user()
    if current_user.role == ROLES['admin']:
        users = User.query.all()
        user_list = []
        for user in users:
            user_dict = {
                'id': user.id,
                'username': user.username,
                'role': get_key(user.role)
        
            }
            user_list.append(user_dict)

        return jsonify(users=user_list)
    
    if current_user.role == ROLES['manager']:
        current_user_id = get_jwt_identity()
        users = User.query.filter_by(manager_id=current_user_id)
        user_list=[]
        for user in users:
            user_dict ={
                'id': user.id,
                'username' : user.username,
                'role' : get_key(user.role)
            }
            user_list.append(user_dict)

        return jsonify(users=user_list)
    
@app.route('/role/<int:user_id>', methods=['PATCH'])
@jwt_required()
def change_role(user_id):
    current_user=get_current_user()
    if current_user.role != ROLES['admin']:
        return jsonify({'message':'Unauthorized Access'}),403
    user=User.query.filter_by(id=user_id).first()

    if user:
        new_role = request.json.get('role')
        if not new_role:
            return jsonify({'message': 'Role is required'}), 400
        if new_role not in ROLES.keys():
            return jsonify({'message': 'Invalid role'}), 400 
        user.role = ROLES[new_role]
        
        db.session.commit()
        return jsonify({'message':'role updated'}),200
    else:
        return jsonify({'error':'User not found'}),404      


@app.route('/employees', methods=['GET'])
def search_employees():
    id = request.json.get('id')
    

    if id:
        employee = User.query.filter_by(id=id).first()
        return jsonify({'username': employee.username , 'role' : get_key(employee.role) })



if __name__ == "__main__":
    app.run(debug=True)