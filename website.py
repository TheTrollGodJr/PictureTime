from flask import Flask, render_template, request, redirect, url_for, make_response
import os
from werkzeug.utils import secure_filename
from PIL import Image, ExifTags
import json
from functools import wraps
import bcrypt
import base64
#from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

PATH = __file__.rsplit("\\", 1)[0].replace("\\", "/")
UPLOAD_FOLDER = PATH + "/data/tempfiles"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ALLOWED_EXTENSIONS"] = {'png', 'jpg', 'jpeg'}

def setupJsonFile(file_path):
    default_content = {"users": [{"username": "guest","password_hash": "JDJiJDEyJGwuSHpEd1lIYWo4YkE3a2tUUEhEd2VoTjluTHhmZnFUQnVXL1NHZU03dm1GU1RjclhhNnNp"}]}
    if not os.path.exists(f"{PATH}/data"): 
        os.mkdir(f"{PATH}/data")
    if not os.path.exists(file_path):
        with open(file_path, 'w') as file:
            json.dump(default_content, file, indent=4)

def loadUser():
    with open(f"{PATH}/data/users.json") as f:
        return json.load(f)['users']
    
def checkPassword(password, hash):
    hashed = base64.b64decode(hash)
    return bcrypt.checkpw(password.encode(), hashed)

def allowedFiles(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

@app.before_request
def checkAuthentication():
    return
    if request.endpoint == "denied": return None
    userAgent = request.headers.get("User-Agent")
    if "Mobi" not in userAgent: return redirect(url_for("denied"))

    # Skip login page so it doesn't redirect to itself
    if request.endpoint == 'login':
        return None

    # Check if the 'auth' cookie is present and valid
    authCookie = request.cookies.get('auth')
    if authCookie != 'authorized':
        # Redirect to login if not authenticated
        return redirect(url_for('login'))
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        users = loadUser()
        for user in users:
            if user['username'] == username and checkPassword(password, user['password_hash']):
                resp = make_response(redirect(url_for("index")))
                resp.set_cookie('auth', 'authorized', max_age=60*60*24*365)
                return resp

    return render_template('login.html')

@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie('auth', '', expires=0)
    return resp

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if 'file' not in request.files:
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        
        if file and allowedFiles(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            return redirect(url_for("submitted"))
    return render_template("index.html")

@app.route("/submitted")
def submitted():
    return render_template("submitted.html")

@app.route("/access-denied")
def denied():
    return render_template("access-denied.html")

@app.errorhandler(404)
def pageNotFound(e):
    return render_template("404.html"), 404

@app.route("/error")
def error():
    msg = request.args.get('error_message', "An unexpected error occurred.")
    return render_template("error.html", error_message=msg), 500

@app.route("/video")
def video():
    return render_template("video.html")

if __name__ == "__main__":
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    setupJsonFile(f"{PATH}/data/users.json")

    app.run(host="0.0.0.0", port=5000)