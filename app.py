from flask import Flask, jsonify, request
from logging.config import dictConfig
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

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})
app = Flask(__name__)
load_dotenv()
app.config['MONGO_URI'] = os.getenv('MONGODB_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
CORS(app)
jwt = JWTManager(app)
mongo = PyMongo(app)


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
            if claims["role"] == "admin":
                return fn(*args, **kwargs)
            if claims["role"] == "super_admin":
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


@app.route('/random-phrase', methods=['GET'])
def random_phrase():
    random_phr = list(mongo.db.phrases.aggregate([{'$sample': {'size': 1}}]))[0]
    sanitized_phr = json.loads(json_util.dumps(random_phr))
    return jsonify({'id': sanitized_phr['_id']['$oid']})


@app.route('/phrases/<id>', methods=['GET'])
def get_phrase(id):
    phrase = mongo.db.phrases.find_one({'_id': ObjectId(id)})
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


@app.route('/create_admin')
@super_admin_required()
def create_admin():
    username = request.json['username']
    password = request.json['password']
    role = request.json['role']

    if mongo.db.users.find_one({'username': username, 'role': role}) is not None:
        return jsonify({'error': 'User already exists'})

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    mongo.db.users.insert_one({'username': username, 'password': hashed, 'role': 'admin'})
    return jsonify()


@app.route('/possible-phrase', methods=['POST'])
def create_possible_phrase():
    text = request.json['text']
    mongo.db.psble_phrases.insert_one({'text': text})
    return jsonify({'msg': 'phrase sent!'})


@app.route('/get-possible-phrases')
@admin_required()
def get_possible_phrases():
    all_possible_phrases = list(mongo.db.psble_phrases.find({}))
    sanitized_phrases = []
    for phr in json.loads(json_util.dumps(all_possible_phrases)):
        sanitized_phrases.append({'id': phr['_id']['$oid'], 'text': phr['text']})
    return jsonify({'phrases': sanitized_phrases})


@app.route('/accept-phrase/<id>', methods=['POST'])
def accept_phrase(id):
    phrase = mongo.db.psble_phrases.find_one({'_id': ObjectId(id)})
    if phrase is None:
        return jsonify({'error': 'phrase does not exist!'})
    mongo.db.phrases.insert_one({'text': phrase['text']})
    mongo.db.psble_phrases.delete_one({'_id': ObjectId(id)})
    return jsonify({'msg': 'phrase accepted!'})


create_super_admin()

# ready: create a route to create admins only for super admins

# todo: create a route to eliminate admins only for super admins

# todo: create a route list all admins

# ready: create a route to post possible phrases posted by anons

# ready: create a route to list all possible phrases

# ready: create a route to accept a possible phrase

# todo: create a route to eliminate a possible phrase
