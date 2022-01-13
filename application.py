from logging import debug
import os
from bson import decode
from bson.son import SON
from flask import Flask
from flask import request
from flask import json
from flask.wrappers import Request
from pymongo import MongoClient
from bson.objectid import ObjectId
from pymongo.collection import ReturnDocument
from werkzeug.exceptions import HTTPException
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
import bcrypt
from datetime import timedelta, datetime
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask import send_file


APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

CORS(app)

# set up flask + jwt config
app.config['JWT_SECRET_KEY'] = 'SHJGDFJHD32467823SDJSDFfd'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=3)
jwt = JWTManager(app)

# Data Base Config

client = MongoClient('mongodb+srv://dako:csol355@cluster0.tqobu.mongodb.net/gundam?retryWrites=true&w=majority')

db = client['gundam']

collection1 = db['gunpla']
collection2 = db['user']

# image set up
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_data(data):
    res = []

    for doc in data:
        doc['_id'] = str(doc['_id'])
        res.append(doc)
    return res

@app.route('/', methods=['GET'])
def index():
    return 'test'

# Get All the Gunpla Kits
# or to create new gunpla kits
@app.route('/api/gunpla', methods=['GET', 'POST'])
def gunpla():
    if request.method == 'GET':
        query = None
        skip = 0
        limit = 0

        if request.query_string:
            grade = request.args.get('grade')

            # Handle page query
            if(request.args.get('page')):
                limit = 5
                skip = (int(request.args.get('page')) - 1) * limit

            # Handle Grade query 
            if grade == 'hg': query = { 'grade': 'High Grade' }
            elif grade == 'rg': query = { 'grade': 'Real Grade' }
            elif grade == 'mg': query = { 'grade': 'Master Grade' }
            elif grade == 'pg': query = { 'grade': 'Perfect Grade' }

        cursor = list(collection1.find(query if query else {}).sort('date', -1).skip(skip).limit(limit))

        num_result = collection1.count_documents(query if query else {})

        data = get_data(cursor)

        return {
            'status': 'success',
            'result': num_result,
            'gunpla': data
        }
    elif request.method == 'POST':
        try:
            files = request.files.getlist('file')

            files_list = []
            for file in files:
                print(file)
                filename = secure_filename(file.filename)
                files_list.append(filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            save_data = {
                'title': request.form.get('title', 'N/A title'),
                'name': request.form.get('name', 'N/A'),
                'img': files_list,
                'grade': request.form.get('grade', 'N/A'),
                'content': request.form.get('content', 'N/A'),
                'date': datetime.now()
            }
            new_id = (collection1.insert_one(save_data)).inserted_id
            data = collection1.find_one({ '_id': new_id })
            data['_id'] = str(data['_id'])

            return {
                'status': 'success',
                'gunpla': data
            }
        except:
            return {
                'status': 'fail',
                'message': 'something went wrong'
            }
        

# Get, Update or Delete Gunpla Kits with the id
@app.route('/api/gunpla/<id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
def gunpla_delete(id):
    if request.method == 'GET':
        try:
            if len(id) < 24:
                return {
                    'status': 'fail',
                    'message': 'error'
                }

            res = collection1.find_one({ '_id': ObjectId(id) })

            res['_id'] = str(res['_id'])

            return {
                'status': 'success',
                'gunpla': res
            }
        except:
            return {
                'status': 'fail',
                'message': 'Something went wrong'
            }, 404
    elif request.method == 'PATCH':
        try:
            res = collection1.find_one_and_update(
                { '_id': ObjectId(id) }, 
                { '$set': request.json },
                return_document=ReturnDocument.AFTER
            )

            res['_id'] = str(res['_id'])

            return {
                'status': 'success',
                'gunpla': res
            }
        except:
            return {
                'status': 'fail',
                'message': 'Something went wrong'
            }, 404
    elif request.method == 'DELETE':
        try:
            collection1.find_one_and_delete(
                {
                    '_id': ObjectId(id),
                },
            )

            return {
                'status': 'success'
            }
        except:
            return {
                'status': 'fail',
                'message': 'Something Went Wrong'
            }, 404

# Display Image
@app.route('/api/image/<name>', methods=['GET'])
def get_image(name):
    try:
        filename = name
        return send_file(f'images\{filename}')
    except:
        return {
            'status': 'fail',
            'message': 'cannot find images'
        }, 404

# Aggregation Pipeline
# Get Newest Images
@app.route('/api/newest', methods=['GET'])
def get_new():
    pipeline = [
        {
            '$addFields': {
                'img': {
                    '$first': '$img'
                }
            }
        },
        {
            '$sort': SON([('date', -1)])
        },
        {
            '$limit': 5
        }
    ]

    res = list(collection1.aggregate(pipeline))

    data = get_data(res)

    return {
        'status': 'success',
        'gunpla': data
    }

# Log In Handler
@app.route('/api/login', methods=['POST'])
def login():
    email = request.json.get('email', None)
    password = request.json.get('password', None)

    if not email or not password:
        return {
            'status': 'fail',
            'message': 'Please provide Email and Password'
        }, 404

    user = collection2.find_one({ 'email': email })

    if not user or not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return {
            'status': 'fail',
            'message': 'Invalid Email or Passowrd'
        }, 400

    user_id = str(user['_id'])

    token = create_access_token(identity=user_id)

    return {
        'staus': 'success',
        'token': token
    }

# Register Handler with special key
@app.route('/api/register', methods=['POST'])
def register():
    secret = request.json.get('secret', None)

    email = request.json.get('email', None)

    password = request.json.get('password', None)

    if not secret or secret != 'DAKO' or not email or not password:
        return {
            'status': 'fail',
            'message': 'Something went wrong with registration'
        }, 404

    user = collection2.find_one({ 'email': email })

    if user:
        return {
            'status': 'fail',
            'message': 'email already taken'
        }, 400

    encode_pw = password.encode()

    hashed_password = bcrypt.hashpw(encode_pw, bcrypt.gensalt())

    collection2.insert_one({
        'email': email,
        'password': hashed_password.decode()
    })

    return {
        'status': 'success'
    }

# Error Handler
@app.errorhandler(HTTPException)
def handle_eception(e):
    response = e.get_response()

    response.data = json.dumps({
        'status': 'fail',
        'message': e.description,
    })

    response.content_type = 'application/json'

    return response