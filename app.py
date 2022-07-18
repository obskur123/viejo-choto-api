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

app = Flask(__name__)
load_dotenv()
app.config['MONGO_URI'] = os.getenv('MONGODB_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
jwt = JWTManager(app)
mongo = PyMongo(app)
CORS(app)


def super_admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["role"] == "super_admin":
                return fn(*args, **kwargs)
            else:
                return jsonify({'msg': "Admins only!"}), 403

        return decorator

    return wrapper


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["role"] == "admin" or claims["role"] == "super_admin":
                return fn(*args, **kwargs)
            else:
                return jsonify({'msg': "Admins only!"}), 403

        return decorator

    return wrapper


def get_user(username, role):
    return mongo.db.users.find_one({'username': username, 'role': role})


def check_user(username, role):
    return True if get_user(username, role) is not None else False


def check_passwd(password, hashed):
    return True if bcrypt.checkpw(password.encode('utf-8'), hashed) else False


def create_super_admin():
    app.logger.info('admin exists!') if check_user(os.getenv('SUPER_ADMIN_USERNAME'), 'super_admin') \
        else mongo.db.users.insert_one({'username': os.getenv('SUPER_ADMIN_USERNAME'),
                                        'password': bcrypt.hashpw(os.getenv('SUPER_ADMIN_PASSWORD').encode('utf-8'),
                                                                  bcrypt.gensalt()),
                                        'role': 'super_admin'})


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


@app.route('/phrase/random', methods=['GET'])
def random_phrase():
    random_phr = list(mongo.db.phrases.aggregate([{'$sample': {'size': 1}}]))[0]
    sanitized_phr = json.loads(json_util.dumps(random_phr))
    return jsonify({'id': sanitized_phr['_id']['$oid']})


@app.route('/phrase/get', methods=['GET'])
def get_phrase():
    phrase = mongo.db.phrases.find_one({'_id': ObjectId(request.args.get('id'))})
    return jsonify({'text': phrase['text']})


@app.route('/login', methods=['POST'])
def login():
    if request.json['role'] == 'admin' or request.json['role'] == 'super_admin':
        if check_user(request.json['username'], request.json['role']):
            user = get_user(request.json['username'], request.json['role'])
            if check_passwd(request.json['password'], user['password']):
                return jsonify({'token': create_access_token(identity=request.json['username'],
                                                             additional_claims={'role': request.json['role']}),
                                'role': request.json['role'],
                                'username': request.json['username']})

    return jsonify({'msg': 'User not found'}), 404


@app.route('/admin/new', methods=['POST'])
@super_admin_required()
def create_admin():
    if mongo.db.users.find_one({'username': request.json['username'], 'role': request.json['role']}) is not None:
        return jsonify({'error': 'User already exists'})
    mongo.db.users.insert_one({'username': request.json['username'],
                               'password': bcrypt.hashpw(request.json['password'].encode('utf-8'), bcrypt.gensalt()),
                               'role': 'admin'})
    return jsonify({'msg': 'User created'})


@app.route('/admin/delete', methods=['DELETE'])
@super_admin_required()
def delete_admin():
    if mongo.db.users.find_one({'_id', ObjectId(request.args.get('id'))}) is None:
        return jsonify({'error': 'id does not exist'})
    mongo.db.users.delete_one({'_id', ObjectId(request.args.get('id'))})
    return jsonify({'msg': 'user deleted successfully'})


@app.route('/admin/get-all')
def get_all_admins():
    users = json.loads(json_util.dumps(list(mongo.db.users.find({}))))
    return jsonify({'admins': list(map(lambda x: {'id': x['_id']['$oid'], 'username': x['username']}, users))})


@app.route('/possible-phrase/new', methods=['POST'])
def create_possible_phrase():
    mongo.db.psble_phrases.insert_one({'text': request.json['text']})
    return jsonify({'msg': 'phrase sent!'})


@app.route('/possible-phrase/get-all', methods=['GET'])
@admin_required()
def get_possible_phrases():
    possible_phrases = json.loads(json_util.dumps(list(mongo.db.psble_phrases.find({}))))
    print(possible_phrases)
    if possible_phrases is None:
        return jsonify({'phrases': []})

    return jsonify({'phrases': list(map(lambda x: {'id': x['_id']['$oid'], 'text': x['text']}, possible_phrases))})


# post request always need a body for some reason
@app.route('/possible-phrase/accept', methods=['POST'])
@admin_required()
def accept_phrase():
    phrase = mongo.db.psble_phrases.find_one({'_id': ObjectId(request.args.get('id'))})
    if phrase is None:
        return jsonify({'error': 'phrase does not exist!'})
    mongo.db.phrases.insert_one({'text': phrase['text']})
    mongo.db.psble_phrases.delete_one({'_id': ObjectId(request.args.get('id'))})
    return jsonify({'msg': 'phrase accepted!'})


@app.route('/possible-phrase/delete', methods=['DELETE'])
@admin_required()
def delete_possible_phrase():
    if mongo.db.psble_phrases.find_one({'_id': ObjectId(request.args.get('id'))}) is None:
        return jsonify({'error': 'id does not exists'})
    mongo.db.psble_phrases.delete_one({'_id': ObjectId(request.args.get('id'))})
    return jsonify({'msg': 'possible phrase removed'})


create_super_admin()

# ready: create a route to create admins only for super admins

# ready: create a route to eliminate admins only for super admins

# ready: create a route list all admins

# ready: create a route to post possible phrases posted by anons

# ready: create a route to list all possible phrases

# ready: create a route to accept a possible phrase

# ready: create a route to eliminate a possible phrase
