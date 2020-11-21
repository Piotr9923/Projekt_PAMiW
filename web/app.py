from flask import Flask, request, make_response, session
from flask_session import Session
from dotenv import load_dotenv
from flask import render_template, flash, url_for
from os import getenv
from bcrypt import hashpw, gensalt, checkpw
from redis import Redis
from datetime import datetime

db=Redis(host='redis',port=6379,db=0)

load_dotenv()

SESSION_TYPE="redis"
SESSION_REDIS=db

# app = Flask(__name__,static_url_path='/static')
app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")
ses = Session(app)


# app.debug = False

def is_user(login):
    return db.hexists(f"user:{login}","password")


def save_user(firstname, lastname, login, email, password, adress):

    print(f"ZAPISUJĘ: {firstname}, {lastname},{login},{email},{password},{adress}")

    salt = gensalt(5)
    password = password.encode()
    adress = adress.encode()
    email = email.encode()
    hashed = hashpw(password,salt)
    db.hset(f"user:{login}","password",hashed)
    db.hset(f"user:{login}", "firstname", firstname)
    db.hset(f"user:{login}", "lastname", lastname)
    db.hset(f"user:{login}", "email", email)
    db.hset(f"user:{login}", "adress", adress)
    return True


def redirect(url, status=301):
    response = make_response('',status)
    response.headers['Location']=url
    return response


def verify_user(login, password):
    password = password.encode()
    hashed = db.hget(f"user:{login}","password")
    if not hashed:
        print(f"ERROR: No password for {login}")
        return False
    return checkpw(password,hashed)


def error(msg,status=400):
    response = make_response({"status":"error","message":msg},status)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/sender/register', methods=['GET'])
def registration_form():
    return render_template("registration.html")


@app.route('/sender/register', methods=['POST'])
def registration():
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    adress = request.form.get("adress")
    email = request.form.get("mail")
    login = request.form.get("login")
    password = request.form.get("password")
    password2 = request.form.get("password2")

    if not firstname:
        flash("Brak imienia")
    if not lastname:
        flash("Brak nazwiska")
    if not adress:
        flash("Brak adresu")
    if not email:
        flash("Brak adresu e-mail")
    if not login:
        flash("Brak nazwy użytkownika")
    if not password:
        flash("Brak hasła")
    if password != password2:
        flash(f"Hasła nie są takie same {password} _ {password2}")
        return redirect(url_for('registration_form'))

    if email and login and password and firstname and lastname and adress:
        if is_user(login):
            flash(f"User {login} istnieje")
            return redirect(url_for('registration_form'))
    else:
        return redirect(url_for('registration_form'))


    success = save_user(firstname,lastname,login,email,password,adress)

    if not success:
        flash("Błąd rejestracji")
        return redirect(url_for('registration_form'))

    return redirect(url_for('login_form'))


@app.route('/sender/login', methods=["GET"])
def login_form():
    return render_template("login.html")


@app.route('/sender/login', methods=["POST"])
def login():
    login = request.form.get("login")
    password = request.form.get("password")

    if not login or not password:
        flash("Brak nazwy użytkownika lub hasła")
        return redirect(url_for('login_form'))

    if not verify_user(login,password):
        flash("Błędna nazwa użytkownika i/lub hasła")
        return redirect(url_for('login_form'))

    flash(f"Welcome {login}!")
    session["login"] = login
    session["logged-at"] = datetime.now()
    return redirect(url_for('index'))


@app.route('/sender/logout')
def sender_logout():

    session.clear()

    return render_template("logout.html")


if __name__ == '__main__':
    app.run(threaded=True, port=5000)
