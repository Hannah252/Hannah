from flask import Flask
from dotenv import load_dotenv
import os
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta

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


from company.user.routes import user
from company.auth.routes import auth
from company.view.routes import view

app.register_blueprint(user, url_prefix = '/user')
app.register_blueprint(auth, url_prefix = '/auth')
app.register_blueprint(view, url_prefix = '/view')