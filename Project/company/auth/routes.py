from flask import jsonify, request, Blueprint
from company import db
from flask_jwt_extended import jwt_required
from company.models import User, get_key, get_current_user, ROLES


auth = Blueprint('auth',__name__)

@auth.route('/new-user', methods=['POST'])
@jwt_required()
def new_user():
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


@auth.route('/manager/<int:user_id>', methods=['PATCH'])
@jwt_required()
def assign_manager(user_id):
    current_user = get_current_user()
    if current_user.role != ROLES['admin']:
        return jsonify({'message':'Unauthorized Access'}),403
    
    user = User.query.filter_by(id=user_id).first()
    if user:
        user.manager_id = request.json.get('manager_id')
        if not user.manager_id:
            return jsonify({'message':'No id provided'}),404
        m_id = user.manager_id
        manager=User.query.filter_by(id=m_id).first()
        if manager:
            if manager.role != ROLES['manager']:
                return jsonify({'message':'The manager id is not found'}),404
            db.session.commit()
            return jsonify({'message':'Manager assigned successfully'}),200
        else:
            return jsonify({'message':'ID not found'}),404
    else:
        return jsonify({'message':'employee not found'}),404


@auth.route('/new-role/<int:user_id>', methods=['PATCH'])
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
        if user.role == ROLES['manager'] and new_role == 'employee':
            employees = User.query.filter_by(manager_id=user.id).all()
            for employee in employees:
                employee.manager_id = None        
        
        user.role = ROLES[new_role]
        db.session.commit()
        return jsonify({'message':'role updated'}),200
    else:
        return jsonify({'error':'User not found'}),404  


@auth.route('/details/<int:user_id>', methods=['PATCH'])
@jwt_required()
def details(user_id):
    
    current_user = get_current_user()
    user=User.query.filter_by(id=user_id).first()
    user_manager=user.manager_id
    if current_user.role != ROLES['admin'] and current_user.id != user_manager:
        return jsonify({'message': 'Unauthorized access'}), 403
    if user:
        user_details=User.query.filter_by(id=user_id).first()

        user_details.full_name = request.json.get('full_name')
        user_details.phone_number = request.json.get('phone_number')
        user_details.email = request.json.get('email')  
    
        if not user_details.full_name and not user_details.phone_number and not user_details.email:
            return jsonify({'error': 'At least one detail is required.'}), 400
        db.session.commit()
        return jsonify({'message': 'Details updated successfully.'}), 200

    else:
        return jsonify({'error':'User not found'}),404