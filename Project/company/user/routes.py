from flask import jsonify, request, make_response, Blueprint
from flask_jwt_extended import create_access_token
from company.models import User

user = Blueprint('user',__name__)

@user.route('/login', methods=['POST'])
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