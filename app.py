import http
from flask import Flask, jsonify, request
from flask_jwt_extended import create_access_token, JWTManager, verify_jwt_in_request, get_jwt
from flask_cors import CORS
from flask_pymongo import PyMongo
from dotenv import load_dotenv
from bson import ObjectId, json_util
from functools import wraps
import bcrypt
import os
import json
import datetime
from webargs import fields
from webargs.flaskparser import use_kwargs


app = Flask(__name__)
load_dotenv()
app.config['MONGO_URI'] = os.getenv('MONGODB_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
jwt = JWTManager(app)
mongo = PyMongo(app)
CORS(app)


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


user_args = {
    'username': fields.Str(required=True),
    'password': fields.Str(required=True),
    'role': fields.Str(required=True, validate=lambda role: role in ['admin', 'super_admin'])
}


def role_required(roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["role"] in roles:
                return fn(*args, **kwargs)
            else:
                return jsonify({'msg': f'You ain\'t got {roles}'}), 403

        return decorator

    return wrapper


def create_super_admin():
    user = mongo.db.users.find_one({'username': os.getenv('SUPER_ADMIN_USERNAME'), 'role': 'super_admin'})
    if user is None:
        mongo.db.users.insert_one({
            'username': os.getenv('SUPER_ADMIN_USERNAME'),
            'password': bcrypt.hashpw(os.getenv('SUPER_ADMIN_PASSWORD').encode('utf-8'), bcrypt.gensalt()),
            'role': 'super_admin'
        })
    else:
        app.logger.info('admin exists!')


def check_user(username, password, role):
    user = mongo.db.users.find_one({'username': username, 'role': role}, {'_id': 0})
    if user is not None:
        return user if bcrypt.checkpw(password.encode('utf-8'), user['password']) else None
    return None


@app.route('/', methods=['GET'])
def index():  # put application's code here
    return '<h1>Nothing to see here dawg.</h1>'


@app.route('/phrase/random', methods=['GET'])
def random_phrase():
    random_phr = list(mongo.db.Phrase.aggregate([{'$sample': {'size': 1}}]))[0]
    sanitized_phr = json.loads(json_util.dumps(random_phr))
    return jsonify({'id': sanitized_phr['_id']['$oid']})


@app.route('/phrase/get', methods=['GET'])
@use_kwargs({'id': fields.Str(required=True)}, location='query')
def get_phrase(id):
    phrase = mongo.db.Phrase.find_one({'_id': ObjectId(id)})
    return jsonify({'text': phrase['text']})


@app.route('/login', methods=['POST'])
@use_kwargs(user_args, location='json')
def login(username, password, role):
    user = check_user(username, password, role)
    if user is None:
        return jsonify({'msg': 'User not found or bad credentials!'}), http.HTTPStatus.NOT_FOUND
    return jsonify({
        'token': create_access_token(identity=user['username'], additional_claims={'role': user['role']}),
        'role': user['role'],
        'username': user['username']
    })


@app.route('/admin/new', methods=['POST'])
@use_kwargs(user_args, location='json')
@role_required(['super_admin'])
def create_admin(username, password, role):
    if mongo.db.users.find_one({'username': username, 'role': role}) is not None:
        return jsonify({'msg': 'User already exists!'}), http.HTTPStatus.CONFLICT
    mongo.db.users.insert_one(
        {
            'username': username,
            'password': bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()),
            'role': 'admin'
        })
    return jsonify({'msg': 'User created!'})


@app.route('/admin/delete', methods=['DELETE'])
@use_kwargs({'id': fields.Str(required=True)}, location='query')
@role_required(['super_admin'])
def delete_admin(id):
    if mongo.db.users.find_one({'_id', ObjectId(id)}) is None:
        return jsonify({'msg': 'User id does not exist!'}), http.HTTPStatus.NOT_FOUND
    mongo.db.users.delete_one({'_id', ObjectId(id)})
    return jsonify({'msg': 'User deleted successfully!'})


@app.route('/admin/get-all', methods=['GET'])
def get_all_admins():
    users = json.loads(json_util.dumps(list(mongo.db.users.find({}))))
    return jsonify({'admins': list(map(lambda x: {'id': x['_id']['$oid'], 'username': x['username']}, users))})


@app.route('/possible-phrase/new', methods=['POST'])
@use_kwargs({'text': fields.Str(required=True)}, location='json')
def create_possible_phrase(text):
    mongo.db.PossiblePhrase.insert_one({'text': text})
    return jsonify({'msg': 'Phrase sent!'})


@app.route('/possible-phrase/get-all', methods=['GET'])
@role_required(['admin', 'super_admin'])
def get_possible_phrase():
    possible_phrase = json.loads(json_util.dumps(list(mongo.db.PossiblePhrase.find({}))))
    return jsonify({'phrases': list(map(lambda x: {'id': x['_id']['$oid'], 'text': x['text']}, possible_phrase))})


# post request always need a body for some reason
@app.route('/possible-phrase/accept', methods=['POST'])
@use_kwargs({'id', fields.Str(required=True)}, location='query')
@role_required(['admin', 'super_admin'])
def accept_phrase(id):
    phrase = mongo.db.PossiblePhrase.find_one({'_id': ObjectId(id)})
    if phrase is None:
        return jsonify({'msg': 'Phrase does not exist!'}), http.HTTPStatus.NOT_FOUND
    mongo.db.Phrase.insert_one({'text': phrase['text']})
    mongo.db.PossiblePhrase.delete_one({'_id': ObjectId(id)})
    return jsonify({'msg': 'Phrase accepted!'})


@app.route('/possible-phrase/delete', methods=['DELETE'])
@use_kwargs({'id': fields.Str(required=True)}, location='query')
@role_required(['admin', 'super_admin'])
def delete_possible_phrase(id):
    if mongo.db.PossiblePhrase.find_one({'_id': ObjectId(id)}) is None:
        return jsonify({'msg': 'Possible phrase id does not exists!'}), http.HTTPStatus.NOT_FOUND
    mongo.db.PossiblePhrase.delete_one({'_id': ObjectId(id)})
    return jsonify({'msg': 'Possible phrase removed!'})


create_super_admin()

# ready: create a route to create admins only for super admins

# ready: create a route to eliminate admins only for super admins

# ready: create a route list all admins

# ready: create a route to post possible Phrase posted by anons

# ready: create a route to list all possible Phrase

# ready: create a route to accept a possible phrase

# ready: create a route to eliminate a possible phrase
