from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
from flask_jwt_extended import get_jwt_identity
from company import db
from company import app

ROLES = {'admin': 0, 'manager': 1, 'employee': 2}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.Integer, nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    full_name = db.Column(db.String(80), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(120), nullable=True)


    def __init__(self,username, password, role, manager_id = None, full_name = None, phone_number = None, email = None):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.role = role
        self.manager_id = manager_id
        self.full_name = full_name
        self.phone_number = phone_number
        self.email = email

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
def get_key(val):
    for key, value in ROLES.items():
        if val == value:
            return key
    

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