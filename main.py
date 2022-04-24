import base64

from flask import Flask, request, jsonify, send_from_directory
import jwt
import os
import uuid
import base64
from dotenv import load_dotenv
from datetime import datetime, timedelta
from database import Database
from database import CursorFromConnectionFromPool
from flask_cors import CORS, cross_origin
import bcrypt
from email_validator import validate_email, EmailNotValidError
from location import location
from checkAuth import auth
from werkzeug.utils import secure_filename

load_dotenv()
DB_PWD = os.getenv('DB_PWD')
DB_USER = os.getenv('DB_USER')
DB_HOST = os.getenv('DB_HOST')

UPLOAD_FOLDER = 'uploads/images/'
ALLOWED_EXTENSIONS={'jpeg', 'png', 'jpg'}
jwtsecret = os.getenv('jwtsecret')
DB = os.getenv('DB')
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
CORS(app)
Database.initialize(user=f'{DB_USER}',
                    password=f'{DB_PWD}',
                    host=f'{DB_HOST}',
                    port=5432,
                    database=f'{DB}')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/users/', methods=['GET'])
@cross_origin()
def get_users():
    try:
        with CursorFromConnectionFromPool() as cursor:
            cursor.execute('select * from users')
            users = cursor.fetchall()
    except:
        return{'message': 'Fetching users failed, please try again later'}
    user_list = []
    for user in users:
        user_tuple_list = list(user)
        user_tuple_list.remove(user_tuple_list[3])
        with CursorFromConnectionFromPool() as cursor:
            cursor.execute('select count(*) from places where userid = %s', (user_tuple_list[0], ))
            user_places_count = cursor.fetchone()

        user_new = {
            'id': user_tuple_list[0], 'image': user_tuple_list[3],
            'name': user_tuple_list[1], 'places': user_places_count,
            'image_type': user_tuple_list[4]
        }
        # user_new = tuple(user_tuple_list)
        user_list.append(user_new)
    return {'users': user_list}


@app.route('/api/users/signup', methods=['POST'])
@cross_origin()
def signup():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password'].encode('utf8')
    file = request.files.get('image')
    binary_file = base64.b64encode(file.read())
    binary_file_decode = binary_file.decode('utf8')
    file_type = file.content_type

    email_error = ''
    valid = ''
    try:
        # Validate.
        valid = validate_email(email)
        # Update with the normalized form.
        email_norm = valid.email
    except EmailNotValidError as e:
        # email is not valid, exception message is human-readable
        email_error = e
        return {'message': email_error}
    if name == '' or valid is False or password == '' or email_error:
        return jsonify({'message': "Invalid inputs passed, please check your data."})
    elif len(password) < 6:
        return {'message':"Password length should be 6 or more characters"}
    else:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_list = filename.split('.')
            file_name = uuid.uuid5(uuid.NAMESPACE_DNS,file_list[0]).hex
            file_list[0] = file_name
            new_filename = '.'.join(file_list)
            path=os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            file.save(path)

        try:
            with CursorFromConnectionFromPool() as cursor:
                cursor.execute('select * from users where email=%s', (email_norm,))
                users = cursor.fetchone()
        except:
            return {'message': 'Signing up failed, please try again later'}
        if users:
            return {'message':"Could not create user, email already exists"}

        salt = bcrypt.gensalt(10)
        hashed = bcrypt.hashpw(password, salt).decode('utf-8')

        try:
            with CursorFromConnectionFromPool() as cursor:
                cursor.execute(f'insert into users(username, email, userpassword, image, image_type)'
                               f'values(%s, %s, %s, %s, %s)', (name, email_norm, hashed, binary_file_decode, file_type))
        except:
            return {"message": "Creating user failed, please try again"}
        # dt = datetime.now() + timedelta(hours=1)
        with CursorFromConnectionFromPool() as cursor:
            cursor.execute('select * from users where email=%s', (email,))
            identified_user = cursor.fetchone()
        payload = {
            'exp': datetime.now() + timedelta(days=1),
            'iat': datetime.now(),
            'id': identified_user[0]
        }
        access_token = jwt.encode(payload, jwtsecret, algorithm="HS256")
        return {'userId': identified_user[0], 'email': identified_user[2], 'token': access_token}


@app.route('/api/users/login', methods=['POST'])
@cross_origin()
def login():
    email = request.json['email']
    password = request.json['password'].encode('utf-8')

    with CursorFromConnectionFromPool() as cursor:
        cursor.execute('select * from users where email=%s', (email, ))
        identified_user = cursor.fetchone()
    if identified_user is None:
        return {'message':"Could not identify user, credentials seem to be wrong"}
    else:
        user_id = identified_user[0]
        password1 = identified_user[3].encode('utf8')
        valid_password = bcrypt.checkpw(password, password1)
    if not valid_password:
        return {'message':'Invalid credentials, could not log you in'}

    # dt = datetime.now() + timedelta(hours=1)
    payload = {
        'exp': datetime.now() + timedelta(days=1),
        'iat': datetime.now(),
        'id': user_id
    }
    access_token = jwt.encode(payload, jwtsecret, algorithm="HS256")
    # print(type(access_token))
    return jsonify({'userId': identified_user[0], 'email': identified_user[2], 'token': str(access_token)})


@app.route('/api/places/<string:pid>', methods=['GET'])
@cross_origin()
def get_place_by_id(pid):
    with CursorFromConnectionFromPool() as cursor:
        cursor.execute('select * from places where placeid = %s', (pid,))
        place_by_id = cursor.fetchone()
    if not place_by_id:
        return 'Could not find a place for the provided id', 404

    coordinates = {'lat': place_by_id[6], 'lng': place_by_id[7]}
    place_item = {
        'id': place_by_id[0], 'title': place_by_id[1], 'description': place_by_id[2],
        'image': place_by_id[3], 'address': place_by_id[4], 'creator': place_by_id[5],
        'location': coordinates
    }
    return {'place': place_item}


@app.route('/api/places/user/<string:uid>', methods=['GET'])
@cross_origin()
def get_places_by_user_id(uid):
    with CursorFromConnectionFromPool() as cursor:
        cursor.execute('select * from places where userid = %s', (uid,))
        places_by_user_id = cursor.fetchall()
    if not places_by_user_id:
        return "Could not find a place for the provided user id.", 404

    places_list = []

    for place_by_user_id in places_by_user_id:
        coordinates = {'lat': place_by_user_id[6], 'lng': place_by_user_id[7]}
        place_item = {
            'id': place_by_user_id[0], 'title': place_by_user_id[1], 'description': place_by_user_id[2],
            'image': place_by_user_id[3], 'address': place_by_user_id[4], 'creator': place_by_user_id[5],
            'location': coordinates
        }
        places_list.append(place_item)
    return {'places': places_list}


@app.route('/api/places', methods=['POST'])
@cross_origin()
def create_place():
    # data = request.headers['Authorization']
    title = request.form['title']
    token = request.headers['Authorization'].split(' ')[1]
    if token == '':
        return 'Authorization failed'
    user_id = auth(token)
    description = request.form['description']
    address = request.form['address']
    file = request.files.get('image')
    binary_file = base64.b64encode(file.read())
    binary_file_decode = binary_file.decode('utf8')
    file_type = file.content_type

    if title == '' or description == '' or address == '' or len(description) < 5:
        return "Invalid inputs passed, please check your data.", 422

    coordinates = location(address)
    latitude = coordinates['lat']
    longitude = coordinates['lng']
    created_place = {
        'title': title, 'description': description, 'address': address,
        'location': coordinates, 'creator': user_id
    }
    with CursorFromConnectionFromPool() as cursor:
        cursor.execute('select * from users where userid=%s', (user_id, ))
        user = cursor.fetchone()
    if not user:
        return "Could not find user for provided id", 404

    with CursorFromConnectionFromPool() as cursor:
        cursor.execute('insert into places(title, description, image, address, userid, latitude, longitude, image_type)'
                       ' values(%s, %s, %s, %s, %s, %s, %s, %s)',
                       (title, description, binary_file_decode, address, user_id, latitude, longitude, file_type))
    return jsonify({'place': created_place}, 201)


@app.route('/api/places/<string:pid>', methods=['PATCH'])
@cross_origin()
def update_place(pid):
    title = request.json['title']
    description = request.json['description']
    address = request.json['address']

    if title == "" or description == '':
        return 'Invalid inputs passed, please check your data', 422

    with CursorFromConnectionFromPool() as cursor:
        cursor.execute('select * from places where placeid = %s', (pid,))
        place_by_id = cursor.fetchone()
    if not place_by_id:
        return 'Could not find a place for the provided id', 404

    token = request.headers['Authorization'].split(' ')[1]
    if token == '':
        return 'Authorization failed'
    user_id = auth(token)

    if place_by_id[5] != user_id:
        return 'You are not allowed to update this place', 401

    with CursorFromConnectionFromPool() as cursor:
        cursor.execute('update places set title=%s, description=%s, address=%s where placeid=%s',
                       (title, description, address, pid))

    return jsonify({'place': place_by_id}, 201)


@app.route('/api/places/<string:pid>', methods=['DELETE'])
@cross_origin()
def delete_place(pid):
    with CursorFromConnectionFromPool() as cursor:
        cursor.execute('select * from places where placeid = %s', (pid,))
        place_by_id = cursor.fetchone()
    if not place_by_id:
        return 'Could not find a place for the provided id', 404

    token = request.headers['Authorization'].split(' ')[1]
    if token == '':
        return 'Authorization failed'
    user_id = auth(token)

    if place_by_id[5] != user_id:
        return 'You are not allowed to delete this place', 401

    with CursorFromConnectionFromPool() as cursor:
        cursor.execute('delete from places where placeid = %s', (pid,))

    return jsonify({'message': 'Deleted place'})


if __name__ == "__main__":
    app.run(debug=True)
