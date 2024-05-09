from flask import Flask, jsonify, request, make_response, send_file
import os
from dataHandler import encrypt, decrypt_file, create_user, sign_in, get_user_files, save_file, delete_file, check_if_admin, get_users, get_all_files_users_view, delete_user, get_activity
import jwt
from datetime import timedelta, datetime
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity, get_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from cryptography.fernet import Fernet

from pathlib import Path

app = Flask(__name__)
CORS(app)
# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = os.env['JWT_KEY'] 
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=7)
jwt = JWTManager(app)



# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/token", methods=["POST"])
def create_token():
    print("TOKEN REQUEST RECIEVED")
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    status,userid = sign_in(username, password)
    if(not status):
        return jsonify({"msg": "Bad username or password"}), 401
    access_token = create_access_token(identity=userid, additional_claims={"username":username})
    return jsonify(access_token=access_token)


@app.route("/register", methods=["POST"])
def register():
    print("Register REQUEST RECIEVED")
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    print(username, password)
    if(not username or not password):
        return jsonify({"msg": "Bad username or password"}), 401
    status = create_user(username, password)
    if(not status):
        return jsonify({"message": "User Exists Try New UserName"}), 400
        
    return jsonify({"message": "Success"}), 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    print("HERE")
    # Access the identity (user ID) and other claims (like username) from the JWT
    current_user_id = get_jwt_identity()
    print(current_user_id)
    print(get_jwt())
    current_user_username = get_jwt()["username"]

    return jsonify(logged_in_as={"user_id": current_user_id, "current_user":current_user_username}), 200


@app.route('/signedin', methods=['GET'])
@jwt_required()
def signedin():
    print("HERE SIGNED IN")
    # Access the identity (user ID) and other claims (like username) from the JWT
    current_user_id = get_jwt_identity()
    print(current_user_id)
    print(get_jwt())
    current_user_username = get_jwt()["username"]
    print("HMM")

    return jsonify({"user_id": current_user_id, "current_user":current_user_username})

@app.route('/isadmin', methods=['GET'])
@jwt_required()
def isadmin():
    print("CHECKING IF ADMIN")
    # Access the identity (user ID) and other claims (like username) from the JWT
    current_user_id = get_jwt_identity()
    print(current_user_id)
    admin = check_if_admin(current_user_id)
    if(admin):
        return {"message":"success"}, 200
    else:
        return {"message":"unauthorized"}, 401

@app.route('/userdata', methods=['GET'])
@jwt_required()
def userdata():
    print("CHECKING IF ADMIN")
    # Access the identity (user ID) and other claims (like username) from the JWT
    current_user_id = get_jwt_identity()
    print(current_user_id)
    admin = check_if_admin(current_user_id)
    if(admin):
        return jsonify(get_users()), 200
    else:
        return {"message":"unauthorized"}, 401

@app.route('/adminfiles', methods=['GET'])
@jwt_required()
def adminfiles():
    print("CHECKING IF ADMIN")
    # Access the identity (user ID) and other claims (like username) from the JWT
    current_user_id = get_jwt_identity()
    print(current_user_id)
    admin = check_if_admin(current_user_id)
    if(admin):
        return jsonify(get_all_files_users_view()), 200
    else:
        return {"message":"unauthorized"}, 401

@app.route('/getactivity', methods=['GET'])
@jwt_required()
def getActivity():
    print("CHECKING IF ADMIN")
    current_user_id = get_jwt_identity()
    print(current_user_id)
    admin = check_if_admin(current_user_id)
    if(admin):
        return jsonify(get_activity()), 200
    else:
        return {"message":"unauthorized"}, 401

@app.route('/recFile', methods=['POST'])
@jwt_required()
def recFile():
    print("HERE REQUEST FILE RECIEVED")
    user = get_jwt_identity()
    file = request.files['file']
    filepath = '/efs/user_files/{}/{}'.format(user, file.filename)
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    print(file.filename, "file in recieve file")
    file.save(filepath)
    # Access the identity (user ID) and other claims (like username) from the JWT
    current_user_id = get_jwt_identity()
    print(current_user_id)
    print(get_jwt(), '<- print get_jwt')
    save_file(file.filename,filepath, current_user_id)
    return {"message":"success"}, 200

@app.route('/getFiles', methods=['GET'])
@jwt_required()
def getFiles():
    # Access the identity (user ID) and other claims (like username) from the JWT
    current_user_id = get_jwt_identity()
    print(current_user_id)
    files_list = get_user_files(current_user_id)
    return jsonify(files_list), 200


@app.route('/getFile', methods=['POST'])
@jwt_required()
def getFile():
    # Access the identity (user ID) and other claims (like username) from the JWT
    current_user_id = get_jwt_identity()
    print(current_user_id)
    fileid = request.json.get('fileid')
    filePath = request.json.get('filepath')
    print(fileid)
    print(filePath)
    if(not filePath or not os.path.exists(filePath)):
        print("HERE")
        return jsonify({"message": "no file id"}), 401
    return send_file(filePath), 200


@app.route('/encryptFile', methods=['POST'])
@jwt_required()
def encryptFile():
    print(request.form)
    print(request)
    print("HERE REQUEST FILE RECIEVED")
    filename = request.json.get('filename')
    filepath = request.json.get('filepath')
    password = request.json.get('password')
    print("filename: ", filename)
    op = encrypt(filepath, "/efs/enc_files/{}".format(filename), password)    
    return send_file(op), 200

@app.route('/deleteFile', methods=['POST'])
@jwt_required()
def deleteFile():
    fileid = request.json.get('fileid')
    current_user_id = get_jwt_identity()
    
    if not fileid:
        return {"message": "NEEDS FILEID"}, 400
    delete_file(fileid, current_user_id)
    return {"message": "succes: file deleted"}, 200

@app.route('/deleteUser', methods=['POST'])
@jwt_required()
def deleteUser():
    print(request.json)
    userid = request.json.get('userid')
    if not userid:
        return {"message": "NEEDS FILEID"}, 400
    delete_user(userid)
    return {"message": "succes: user deleted"}, 200


@app.route('/decryptFile', methods=['POST'])
def decryptFile():
    print('HERE GOT REQUEST')
    file = request.files['file']
    password = request.form.get('password')
    filepath = '/efs/dec_files/{}'.format(file.filename)
    file.save(filepath)
    if not file or not password:
        try:
            os.system("rm {}".format(filepath))
        except:
            print("can't remove filepath")
        return {"message": "NEEDS A File and password"}, 400
    success, dc = decrypt_file(filepath, password, file.filename)
    if not success:
        return {"message": "BAD PASSWORD"}, 400
    return send_file(dc), 200



@app.route("/test", methods=['GET'])
def test():
    return "TEST WORKING"


if(__name__ == '__main__'):
    app.run(debug=True)
