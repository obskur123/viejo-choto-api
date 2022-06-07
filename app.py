from flask import Flask, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
from dotenv import load_dotenv
from bson import ObjectId, json_util
import os
import json

app = Flask(__name__)
load_dotenv()
app.config['MONGO_URI'] = os.getenv('MONGODB_URI')
CORS(app)
mongo = PyMongo(app)


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


# if __name__ == '__main__':
#     app.run()
