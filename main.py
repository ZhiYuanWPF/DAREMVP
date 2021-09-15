import socket
import ssl

from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt

from requests import get

from functools import wraps
from datetime import datetime

import os
import re
import pyotp
import pymongo

# connect to mongodb
client = pymongo.MongoClient("mongodb://localhost:27017/")

mongo_catalog = client["DAREMVP"]["menucatalog"]
mongo_cred = client["DAREMVP"]["credentials"]

# mongo-related operations
def mongo_get_entire_catalog():
    try:
        all_items = list(mongo_catalog.find())
        for item in all_items:
            del item['_id']
        return all_items

    except pymongo.errors.PyMongoError as e:
        return []

def mongo_update_catalog(original_id, updated_id, updated_name, updated_price):
    try:
        result = mongo_catalog.update_one({"id": original_id},
                                           {"$set": {"id": updated_id, "price": updated_price, "name": updated_name}})
        return result.matched_count > 0
    except pymongo.errors.PyMongoError as e:
        return False

def mongo_add_catalog(id, name, price):
    try:
        insert_document = {"id": id, "price": price,"name": name}
        x = mongo_catalog.insert_one(insert_document)
        if x.acknowledged is True:
            return x.acknowledged
        else:
            return False
    except Exception as e:
        return False

def mongo_delete_catalog(id):
    try:
        mongo_catalog.delete_one({"id": id})
        all_items = mongo_catalog.find({"id": id})
        for item in all_items:
            return False
        return True

    except Exception as e:
        return False

def mongo_does_id_exist(id):
    try:
        result = mongo_catalog.find_one({"id": id})
        if result is None:
            return False
        else:
            return True
    except pymongo.errors.PyMongoError as e:
        return None

def mongo_does_username_exist(username):
    try:
        result = mongo_cred.find_one({"username": username})
        if result is None:
            return False
        else:
            return True
    except pymongo.errors.PyMongoError as e:
        return False


def mongo_authenticate_user(username, password):
    try:
        result = mongo_cred.find_one({"username": username})
        password_hash = result['password']
        hash_comparison = bcrypt.check_password_hash(password_hash, password)

        if hash_comparison is False:
            return False
        else:
            return result['auth_secret']

    except pymongo.errors.PyMongoError as e:
        return None

def mongo_add_credentials(username, password):
    try:
        second_factor_secret = pyotp.random_base32()

        # hash and salt password with Bcrypt
        bcrypt_pw = bcrypt.generate_password_hash(password).decode('ascii')

        insert_document = {"username": username, "password": bcrypt_pw, "role": "user", "auth_secret": second_factor_secret}
        x = mongo_cred.insert_one(insert_document)
        if x.acknowledged is True:
            return second_factor_secret
        else:
            return False
    except Exception as e:
        return False

# authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect('/login')
        else:
            return f(*args, **kwargs)
    return decorated

# input validation
def is_price_valid(price_value):
    # check if price is non-negative + numerical value + at most 2dp
    regex_check = re.search('^(\d)+(\.\d{1,2})?$', price_value)
    if regex_check is None:
        return 'Update failed. Entered price is not valid.'

    try:
        updated_price = float(price_value)
        if updated_price <= 0:
            return 'Update failed. Entered price cannot be zero or negative.'

        return True

    except ValueError:
        return 'Update failed. Entered price is not valid.'

def check_is_alphanumeric_and_space_hyphen(value):
    regex_match = re.search('^[a-zA-Z 0-9\-]*$', value)
    return regex_match is not None


def is_password_valid(password):
    regex_match = re.search('(?=^.{8,64}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?=.*[A-Z])(?=.*[a-z]).*$', password)
    return regex_match is not None

def is_username_valid(username):
    regex_match = re.search('^[a-zA-Z0-9]{4,64}$', username)
    return regex_match is not None

# resolve current web server IP address
ip_addr = get('https://api.ipify.org').text

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
server_port = 8443
server_FQDN = 'https://' + ip_addr + ':' + str(server_port)

bcrypt = Bcrypt(app)

# to fix issue with certain FireFox and Chrome
cors = CORS(app, resources={r"/foo": {"origins": ip_addr}})

app.config["SECRET_KEY"] = "APP_SECRET_KEY"
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["2000 per hour"]
)

# make logging directory if not exist
if not os.path.exists('logs'):
    os.makedirs('logs')
logfile_name = 'logs/custom_log_' + datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + '.log'

@app.route('/landing', methods=["GET"])
@requires_auth
def landing():
    return render_template('pg_listmenu.html', userinfo={'name': session['logged_in']}, ip_addr=server_FQDN), 200


@limiter.limit("5 per minute")
@app.route('/get_catalog')
@requires_auth
def get_catalog():
    entire_menu = mongo_get_entire_catalog()
    jsonified_response = {"resp": entire_menu}

    return jsonified_response

@limiter.limit("5 per minute")
@app.route('/update_catalog', methods=['POST'])
@requires_auth
def update_catalog():
    # to check if data is correct
    resp = {'updated': False, "message": ""}

    form = request.form
    # check for missing param
    if 'original_id' in form and 'updated_id' in form and 'updated_name' in form and 'updated_price' in form:
        original_id = form['original_id']
        updated_id = form['updated_id']
        updated_name = form['updated_name']
        updated_price = form['updated_price']

        # additional checks for data sanity
        # check if the values of the IDs and name consists of just alphanumeric characters and hyphen
        regex_check_oid = check_is_alphanumeric_and_space_hyphen(original_id)
        if regex_check_oid is False:
            resp['message'] = 'Update failed. Unexpected value received.'
            return resp

        regex_check_nid = check_is_alphanumeric_and_space_hyphen(updated_id)
        if regex_check_nid is False:
            resp['message'] = 'Update failed. Ensure new ID only consists of just alphanumeric characters, spaces and hyphens.'
            return resp

        regex_check_name = check_is_alphanumeric_and_space_hyphen(updated_name)
        if regex_check_name is False:
            resp['message'] = 'Update failed. Ensure new name only consists of just alphanumeric characters, spaces and hyphens.'
            return resp

        # check if old ID exists
        if mongo_does_id_exist(original_id) is False:
            # old ID does not exist, not updating a valid record
            resp['message'] = 'Update failed. Invalid record observed.'
            return resp

        # check if user is attempting to update ID
        if original_id != updated_id and mongo_does_id_exist(updated_id):
            # new ID exists, cannot update duplicate ID
            resp['message'] = 'Update failed. The ID that you are trying to update to is already being used.'
            return resp

        # check if price is non-negative + numerical value + at most 2dp
        price_check_results = is_price_valid(updated_price)
        if price_check_results is not True:
            resp['message'] = price_check_results
            return resp

        updated_price = float(updated_price)

        # no errors, update here
        resp['updated'] = mongo_update_catalog(original_id, updated_id, updated_name, updated_price)

        if resp['updated'] is False:
            resp['message'] = 'Update failed. Unable to update database.'
            return resp
    else:
        resp['message'] = 'Update failed. Missing data recorded.'
        return resp

    resp['message'] = "Update was successful. Changes will be reflected."
    resp['new_table_info'] = mongo_get_entire_catalog()
    return resp


@limiter.limit("5 per minute")
@app.route('/add_catalog', methods=['POST'])
@requires_auth
def add_catalog():
    # to check if data is correct
    resp = {'added': False, "message": ""}

    form = request.form
    # check for missing param
    if 'id' in form and 'name' in form and 'price' in form:
        id = form['id']
        name = form['name']
        price = form['price']

        # additional checks for data sanity
        # check if the values of the ID and name consists of just alphanumeric characters and hyphen
        regex_check_nid = check_is_alphanumeric_and_space_hyphen(id)
        if regex_check_nid is False:
            resp[
                'message'] = 'Update failed. Ensure new ID only consists of just alphanumeric characters, spaces and hyphens.'
            return resp

        regex_check_name = check_is_alphanumeric_and_space_hyphen(name)
        if regex_check_name is False:
            resp['message'] = 'Update failed. Ensure new name only consists of just alphanumeric characters, spaces and hyphens.'
            return resp

        # check if old ID exists
        if mongo_does_id_exist(id) is True:
            # old ID exists, cannot add multiple record with same ID
            resp['message'] = 'Addition failed. Existing record observed with same ID. Please enter another ID.'
            return resp

        # check if price is non-negative + numerical value + at most 2dp
        price_check_results = is_price_valid(price)
        if price_check_results is not True:
            resp['message'] = price_check_results
            return resp

        price = float(price)

        # no errors, update here
        resp['added'] = mongo_add_catalog(id, name, price)

        if resp['added'] is False:
            resp['message'] = 'Update failed. Unable to update database.'
            return resp

    else:
        resp['message'] = 'Update failed. Missing data recorded.'
        return resp

    resp['message'] = "Update was successful. Changes will be reflected."
    resp['new_table_info'] = mongo_get_entire_catalog()
    return resp


@limiter.limit("5 per minute")
@app.route('/delete_catalog', methods=['POST'])
@requires_auth
def delete_catalog():
    # to check if data is correct
    resp = {'deleted': False, "message": ""}

    form = request.form
    # check for missing param
    if 'id' in form:
        id = form['id']

        # check if the values of the IDs and name consists of just alphanumeric characters and hyphen
        regex_check_oid = check_is_alphanumeric_and_space_hyphen(id)
        if regex_check_oid is False:
            resp['message'] = 'Update failed. Unexpected value received.'
            return resp

        # check if old ID exists
        if mongo_does_id_exist(id) is False:
            # old ID does not exist, not updating a valid record
            resp['message'] = 'Update failed. Record with supplied ID does not exist.'
            return resp

        # no errors, delete here
        resp['deleted'] = mongo_delete_catalog(id)

        if resp['deleted'] is False:
            resp['message'] = 'Deletion failed. Unable to delete record from database.'
            return resp

    else:
        resp['message'] = 'Deletion failed. Missing data recorded.'
        return resp

    resp['message'] = "Deletion was successful. Changes will be reflected."
    resp['new_table_info'] = mongo_get_entire_catalog()
    return resp

@limiter.limit("5 per minute")
@app.route('/logout')
@requires_auth
def logout():
    session.pop('logged_in', None)
    return redirect('/login')

# login page route
@limiter.limit("10 per minute")
@app.route('/')
@app.route("/login")
@app.route("/login/")
def login():
    if 'logged_in' in session:
        return redirect('/landing')
    else:
        return render_template("pg_login.html", ip_addr=server_FQDN)

# login form route
@limiter.limit("5 per minute")
@app.route("/login_attempt", methods=["POST"])
def login_form():
    # to check if data is correct
    resp = {'authenticated': False, "message": ""}

    form = request.form
    # check for missing param
    if 'user' in form and 'pass' in form:
        user = form['user']
        password = form['pass']

        authentication_result = mongo_authenticate_user(user, password)

        if authentication_result is False:
            resp['message'] = 'Authentication Failed. Invalid username or password.'
            return resp

    else:
        resp['message'] = 'Authentication Failed. Missing data recorded.'
        return resp

    resp['message'] = 'Authentication success. Please enter your 2FA token.'
    resp['authenticated'] = True
    return resp

# second_factor authentication API
@limiter.limit("5 per minute")
@app.route("/second_factor", methods=["POST"])
def second_factor():
    # to check if data is correct
    resp = {'authenticated': False, "message": ""}

    form = request.form
    # check for missing param
    if 'user' in form and 'pass' in form and 'second_factor' in form:
        user = form['user']
        password = form['pass']
        second_factor = form['second_factor']

        authentication_result = mongo_authenticate_user(user, password)

        if authentication_result is False:
            resp['message'] = 'Authentication Failed. Invalid username or password or token.'
            return resp
        else:
            totp_token = authentication_result
            expected_totp_token_value = pyotp.TOTP(totp_token).now()

            # check totp
            if str(expected_totp_token_value) != str(second_factor):
                resp['message'] = 'Authentication Failed. Invalid username or password or token.'
                return resp
            else:
                # store session information
                session['logged_in'] = user

    else:
        resp['message'] = 'Authentication Failed. Missing data recorded.'
        return resp

    resp['authenticated'] = True
    resp['message'] = 'Authentication Success. Redirecting.'
    return resp


# second_factor authentication API
@limiter.limit("5 per minute")
@app.route("/enrollment", methods=["POST"])
def enrollment():
    # to check if data is correct
    resp = {'success': False, "message": ""}

    form = request.form
    # check for missing param
    if 'username_enrollment' in form and 'password_enrollment' in form:
        username_enrollment = form['username_enrollment'].strip()
        password_enrollment = form['password_enrollment']

        if username_enrollment == "" or password_enrollment == "":
            resp['message'] = 'Enrollment Failed.'
            return resp

        if mongo_does_username_exist(username_enrollment):
            resp['message'] = 'Enrollment Failed.'
            return resp

        if not is_username_valid(username_enrollment):
            resp['message'] = 'Enrollment Failed. Please ensure that the username and password both adhere to the requirements.'
            return resp

        # check if password is in password policy
        if not is_password_valid(password_enrollment):
            resp['message'] = 'Enrollment Failed. Please ensure that the username and password both adhere to the requirements.'
            return resp

        second_factor_secret = mongo_add_credentials(username_enrollment, password_enrollment)

        if second_factor_secret is False:
            resp['message'] = "Something went wrong."
            return resp

        # put totp payload
        totp_string = pyotp.totp.TOTP(second_factor_secret).provisioning_uri(name=username_enrollment, issuer_name='Uncle Roger Wok Way')

        resp['TOTP_STRING'] = totp_string
        resp['message'] = "Please scan the generated QR code and close the window once you are done."

    else:
        resp['message'] = 'Enrollment Failed. Missing data recorded.'
        return resp

    resp['success'] = True
    return resp

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    del response.headers['Expires']
    del response.headers['ETag']
    response.headers['Server'] = "SuperServer"

    # logger
    if 'logged_in' in session:
        user = session['logged_in']
    else:
        user = '-'

    server_ip = str(socket.gethostname())
    QUERY_STRING = str(request.environ['QUERY_STRING'])
    if QUERY_STRING == '':
        QUERY_STRING = '-'

    logging_details = str(request.environ['REMOTE_ADDR']) + ', ' + user + ', ' + datetime.now().strftime('%d/%m/%Y, %H:%M:%S') + ', Flask, SERVER, ' \
            + server_ip + ', -, -, -, ' + str(response.status_code) + ', ' + '0, ' + str(request.environ['REQUEST_METHOD']) + ', ' + str(request.environ['REQUEST_URI']) + ', ' + QUERY_STRING + '\n'
    with open(logfile_name, 'a') as f:
        f.write(logging_details)

    return response

# error handlers
@app.errorhandler(404)
def page_not_found(error):
    print(error)
    if 'logged_in' in session:
        if session['logged_in']:
            return render_template('pg_404.html', userinfo={'name': session['logged_in']}), 404

    return render_template('pg_404.html', userinfo=None), 404

# rate limit hit
@app.errorhandler(429)
def ratelimit_handler(error):
    print(error)
    if 'logged_in' in session:
        if session['logged_in']:
            return render_template('pg_429.html', userinfo={'name': session['logged_in']}), 200

    return render_template('pg_429.html', userinfo=None), 200


# run over HTTPS
ciphersuite_list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384"
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.set_ciphers(ciphersuite_list)
context.load_cert_chain("https/cert.pem", "https/key.pem")

app.run(host=ip_addr, port=server_port, ssl_context=context)
