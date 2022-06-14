# viejo-choto-api
<<<<<<< HEAD
flask api for my viejo-choto app, all comes down to a couple endpoints to fetch random phrases of some old argentinian guy.

My frontend its a QuasarJS app, and I use it to fetch the data from this api.
# Endpoints
### /random-phrase
```python
@app.route('/random-phrase', methods=['GET'])
def random_phrase():
    random_phr = list(mongo.db.phrases.aggregate([{'$sample': {'size': 1}}]))[0]
    sanitized_phr = json.loads(json_util.dumps(random_phr))
    return jsonify({'id': sanitized_phr['_id']['$oid']})
```
### returns
```json
{ "id": "string" }
```

### /phrases/-id-
```python
@app.route('/phrases/<id>', methods=['GET'])
def get_phrase(id):
    phrase = mongo.db.phrases.find_one({'_id': ObjectId(id)})
    print(phrase)
    return jsonify({'text': phrase['text']})
```
### returns
```json
{ "text": "string" }
```
=======
flask api for my viejo-choto app
>>>>>>> ecd966c56374f2d6ba722004fa5f0b251b3d62fc
