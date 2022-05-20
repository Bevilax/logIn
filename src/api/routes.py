"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, Account
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from argon2 import PasswordHasher

api = Blueprint('api', __name__)

ph = PasswordHasher()

@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

#creating the user
@api.route('/register', methods=['POST'])
def register():
    payload = request.get_json() 
    
    user = User(
        email=payload['email'], 
        password=ph.hash(payload['password']), 
        is_active=True
    )

    #adding the model to the session/sending the user to the database
    db.session.add(user)
    db.session.commit()

    return "user registered", 200

#login endpoint starts below

@api.route('/login', methods=['POST'])
def login():
    payload = request.get_json()

    user = User.query.filter(User.email == payload['email']).first()
    if user is None:
        return 'failed-authentication', 401
    if user.password != payload ['password']:
        return 'failed-authentication', 401
    
    token = create_access_token (identity=user.id)

    return jsonify({'token': token})

#creating a protected endpoint (requires access the user information)

@api.route('/accounts', methods=['GET'])
@jwt_required()
def accounts():
    user_id = get_jwt_identity()

    user = User.query.get(user_id)
    accounts = Account.query.filter(Account.user_id==user_id).all()

    account_info = { 
        "accounts": [x.serialize() for x in accounts],
        "user": user.serialize()
    }

    return jsonify(account_info)

