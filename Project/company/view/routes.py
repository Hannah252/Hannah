from flask import jsonify, request, Blueprint
from flask_jwt_extended import jwt_required, get_jwt_identity
from company.models import User, get_key, get_current_user, ROLES

view = Blueprint('view',__name__)

@view.route('/list', methods=['GET'])
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

        return jsonify(reportees=user_list)
    

@view.route('/roles', methods=['GET'])
def search_employees():

    role = request.json.get('role')

    if role:
        employees = User.query.filter_by(role=ROLES[role])

        employee_list = [{'id': e.id, 'username': e.username, 'role': get_key(e.role)} for e in employees]

        return jsonify(employees=employee_list)
    if not role:
        return jsonify({'message':'Enter role'}),400


@view.route('/search', methods=['GET'])
def search_details():
    id=request.json.get('id')
    if not id:
        return jsonify({'message':'Enter ID'}), 400
    user_details=User.query.filter_by(id=id).first()
    if not user_details:
        return jsonify({'message':'User not found'}), 404    
    manager = User.query.filter_by(id=user_details.manager_id).first()
    manager_name = manager.full_name if manager else None
    return jsonify({
        'username': user_details.username,
        'role' : get_key(user_details.role),
        'manager id' : user_details.manager_id,
        'reporting to' : manager_name,
        'Full name' : user_details.full_name,
        'email' : user_details.email,
        'Phone number' : user_details.phone_number
    })