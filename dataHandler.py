import base64
import time
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity, get_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from cryptography.fernet import Fernet
import hashlib

import psycopg2
import os

def get_conn_cursor() -> psycopg2.extensions.cursor:
    conn = psycopg2.connect(
        host=os.env['rds_link'],
        database="final_project",
        port='5432',
        user="postgres",
        password=os.env['password_pgql'])
    cur = conn.cursor()
    return conn, cur


def select_sql(sql):
    conn,cursor = get_conn_cursor()
    cursor.execute(sql)
    return cursor.fetchall()

def encrypt(filepath,outputpath, password):
    password = password.encode('utf-8')
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    with open(filepath, 'rb') as file_bytes:
        data = file_bytes.read()

    encrypted = f.encrypt(data)
    encrypted+=salt
    conn, cursor =get_conn_cursor()
    log_activity(conn, cursor, "encrypt file")
    with open(outputpath, 'wb') as encryptedfile:
        encryptedfile.write(encrypted)
    return outputpath



def decrypt_file(file, password, filename):
    try:
        password = password.encode('utf-8')
        with open(file, 'rb') as enc_file:
            data = enc_file.read()
        enc_file.close()
        # remove the last 16 bytes of the file for the salt
        salt = data[-16:]
        data = data.split(salt)[0]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        decd = f.decrypt(data)
        with open('/efs/decrypt_files/{}'.format(filename), 'wb') as encryptedfile:
            encryptedfile.write(decd)
        return True, '/efs/decrypt_files/{}'.format(filename)
    except:
        return False, "bad password"

def check_user_exists(username):
    sql = f"SELECT * FROM users WHERE username='{username}'"
    res = select_sql(sql)
    if(len(res) == 0):
        return False
    return True

def create_user(username,password):
    hashed_password =str(hashlib.sha256(password.encode()).hexdigest())
    print(hashed_password)
    conn, cursor = get_conn_cursor()
    user_exists = check_user_exists(username)
    if(user_exists):
        return False
    insert_user_sql = f'''INSERT INTO public.users(username, password) VALUES('{username}', '{hashed_password}')'''

    cursor.execute(insert_user_sql)
    conn.commit()
    print("Created user {} with username".format(username))
    log_activity(conn, cursor, "new user")
    return True

def sign_in(username, password):
    get_user_sql = f"SELECT * FROM public.users WHERE username='{username}'"
    submitted_hashed_pass = str(hashlib.sha256(password.encode()).hexdigest())
    conn,cursor = get_conn_cursor()
    cursor.execute(get_user_sql)
    res = cursor.fetchall()
    if(not (res)):
        return False, 0
    hashed_pass = res[0][1]
    userid = res[0][2]
    log_activity(conn, cursor, "login", userid=userid)
    succ = (hashed_pass == submitted_hashed_pass)
    if(succ):
        return True, userid
    else:
        return False, 0

def check_if_admin(user_id):
    try:
        get_user_sql = f"select isadmin from users where userid={user_id}"
        conn,cursor = get_conn_cursor()
        cursor.execute(get_user_sql)
        res = cursor.fetchall()
        return res[0][0]
    except:
        return False

def save_file(filename, filepath, userid):
    print("CALLED THIS")
    conn,cursor = get_conn_cursor()
    sql = f''' 
        INSERT INTO public.files(
            filename, filepath, userid)
            VALUES ('{filename}', '{filepath}', {userid});
    '''
    cursor.execute(sql)
    conn.commit()
    return True

def get_user_files(userid):
    sql = f''' 
        SELECT filename, filepath, userid, fileid
	    FROM public.files
        WHERE userid={userid};
    '''
    results = select_sql(sql)
    final_list =[]
    for result in results:
        final_list.append({"filename":result[0],"filepath":result[1],"fileid":result[3]})
    return final_list

def delete_file(fileid, userid):
    try:
        conn,cursor = get_conn_cursor()
        get_path_sql = f'''
            SELECT filepath FROM files WHERE fileid={fileid}
        '''
        cursor.execute(get_path_sql)
        fp = cursor.fetchall()
        filepath=fp[0][0]
        os.system("rm {}".format(filepath))
        sql = f''' 
            DELETE FROM public.files
            WHERE fileid={fileid}
        '''
        cursor.execute(sql)
        conn.commit()
        print("DELETING FILE WITH FILEID: {}".format(fileid))
        log_activity(conn, cursor, "delete file", userid=userid, fileid=fileid)
        return True
    except Exception as e:
        print(e)
        return False

def delete_user(userid):
    try:
        conn,cursor = get_conn_cursor()
        sql = f''' 
            DELETE FROM public.users
            WHERE userid={userid}
        '''
        cursor.execute(sql)
        conn.commit()
        print("DELETING user WITH FILEID: {}".format(userid))
        return True
    except Exception as e:
        print(e)
        return False
        
def get_users():
    conn,cursor = get_conn_cursor()
    sql = "select username,userid,isadmin from users"
    cursor.execute(sql)
    res = cursor.fetchall()
    final = []
    for row in res:
        final.append({"username":row[0], "userid":row[1], "isadmin":row[2]})
    return final

def get_all_files_users_view():
    sql = 'select u.username, u.userid, f.filename, f.fileid from users u join files f on u.userid = f.userid;'
    res = select_sql(sql)
    final = []
    print(res)
    for row in res:
        final.append({"username":row[0], "userid": row[1], "filename":row[2],"fileid":row[3]})
    return final

def get_activity():
    sql = 'select * from activity;'
    res = select_sql(sql)
    final = []
    for row in res:
        final.append({"activity":row[0], "timestamp": row[1], "activityid":row[2],"userid":row[3], "fileid": row[4]})
    return final

def log_activity(dbcon,cursor, activity, userid='null', fileid='null'):
    sql = f'''
        INSERT into activity (activity, userid, fileid, "timestamp")
        VALUES ('{activity}', {userid}, {fileid}, NOW());
    '''
    cursor.execute(sql)
    dbcon.commit()
    return True


if __name__ == '__main__':
    pass
