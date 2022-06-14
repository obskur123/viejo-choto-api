from flask import Flask, jsonify, request, make_response
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, verify_jwt_in_request, \
    get_jwt
from flask_cors import CORS
from flask_pymongo import PyMongo
from dotenv import load_dotenv
from bson import ObjectId, json_util
from functools import wraps
import bcrypt
import os
import json

app = Flask(__name__)
load_dotenv()
app.config['MONGO_URI'] = os.getenv('MONGODB_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
CORS(app)
jwt = JWTManager(app)
mongo = PyMongo(app)


class BadUsernameException(Exception):
    pass


class BadPasswordException(Exception):
    pass


def super_admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["role"] == "super_admin":
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Super admins only!"), 403

        return decorator

    return wrapper


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["role"] == "admin":
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Admins only!"), 403

        return decorator

    return wrapper


def create_super_admin():
    user = mongo.db.users.find_one({'username': 'viejo', 'role': 'super_admin'})
    if user is None:
        hashed = bcrypt.hashpw(os.getenv('SUPER_ADMIN_PASSWORD').encode('utf-8'), bcrypt.gensalt())
        mongo.db.users.insert_one({'username': 'viejo', 'password': hashed, 'role': 'super_admin'})
        print('Super admin created')
    else:
        print('Super admin already exists')


create_super_admin()


def check_user(username, role):
    user = mongo.db.users.find_one({'username': username, 'role': role})
    if user is None:
        raise BadUsernameException
    return user


def check_passwd(password, hashed):
    if bcrypt.checkpw(password.encode('utf-8'), hashed):
        return True
    raise BadPasswordException


# @app.after_request
# def refresh_expiring_jwts(response):
#     try:
#         exp_timestamp = get_jwt()["exp"]
#         now = datetime.now(timezone.utc)
#         target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
#         if target_timestamp > exp_timestamp:
#             access_token = create_access_token(identity=get_jwt_identity())
#             set_access_cookies(response, access_token)
#         return response
#     except (RuntimeError, KeyError):
#         # Case where there is not a valid JWT. Just return the original response
#         return response


@app.route('/', methods=['GET'])
def hello_world():  # put application's code here
    return 'Nothing to see here dawg.'


@app.route('/random-phrase', methods=['GET'])
def random_phrase():
    random_phr = list(mongo.db.phrases.aggregate([{'$sample': {'size': 1}}]))[0]
    sanitized_phr = json.loads(json_util.dumps(random_phr))
    return jsonify({'id': sanitized_phr['_id']['$oid']})


@app.route('/phrases/<id>', methods=['GET'])
def get_phrase(id):
    phrase = mongo.db.phrases.find_one({'_id': ObjectId(id)})
    print(phrase)
    return jsonify({'text': phrase['text']})


@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    print(password)
    role = request.json['role']
    try:
        if role == 'admin':
            user = check_user(username, 'admin')
            if check_passwd(password, user['password']):
                return jsonify({'token': create_access_token(identity=username,
                                                             additional_claims={'role': 'admin'})})
        elif role == 'super_admin':
            user = check_user(username, 'super_admin')
            if check_passwd(password, user['password']):
                return jsonify({'token': create_access_token(identity=username,
                                                             additional_claims={'role': 'super_admin'})})
    except BadUsernameException:
        return make_response(jsonify({'error': 'Bad username'}), 400)
    except BadPasswordException:
        return make_response(jsonify({'error': 'Bad password'}), 400)


@app.route('/super_admin_only', methods=['GET'])
@super_admin_required()
def super_admin_only():
    return jsonify({'msg': 'You are a super admin!'})

# todo: create a route to create admins only for super admins

# todo: create a route to eliminate admins only for super admins

# todo: create a route list all admins

# todo: create a route to post possible phrases posted by anons

# todo: create a route to list all possible phrases

# todo: create a route to accept a possible phrase

# todo: create a route to eliminate a possible phrase
