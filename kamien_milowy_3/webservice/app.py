from flask import Flask, request, make_response, g
from dotenv import load_dotenv
from flask import render_template, flash, url_for
from os import getenv
from bcrypt import hashpw, gensalt, checkpw
from redis import StrictRedis
from datetime import datetime
from uuid import uuid4
from jwt import encode, decode
from redis.exceptions import ConnectionError
import jwt
from flask_hal import HAL
from flask_hal.document import Document, Embedded
from flask_hal.link import Link
import json

app = Flask(__name__)
HAL(app)
load_dotenv()

REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
if REDIS_HOST:
    db = StrictRedis(REDIS_HOST, db=25, password=REDIS_PASS, port=6379)
else:
    db = StrictRedis(host='redis', port=6379, db=0)

SESSION_TYPE = "redis"
SESSION_REDIS = db
SESSION_COOKIE_HTTPONLY = True
JWT_SECRET = getenv("JWT_SECRET")

app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")

app.debug = False


@app.before_request
def before():
    token = request.headers.get("Authorization","").replace("Bearer","")
    try:
        g.authorization = decode(token, JWT_SECRET, algorithms=["HS256"])
        print("Authorized "+str(g.authorization))
    except Exception as e:
        print("Unauthorized "+str(e))
        g.authorization = {}


def generate_delete_token(label, login):
    payload = {
        "iss": "label auth server",
        "sub": label,
        "usr": login,
        "aud": "label delete service"
    }
    token = encode(payload, JWT_SECRET, algorithm='HS256')
    return token


def is_database_available():
    try:
        db.ping()
    except ConnectionError:
        return False
    return True


def is_user(login):
    return db.hexists(f"user:{login}", "password")


def save_user(firstname, lastname, login, email, password, adress):

    salt = gensalt(5)
    password = password.encode()
    adress = adress.encode()
    email = email.encode()
    hashed = hashpw(password, salt)
    db.hset(f"user:{login}", "password",hashed)
    db.hset(f"user:{login}", "firstname", firstname)
    db.hset(f"user:{login}", "lastname", lastname)
    db.hset(f"user:{login}", "email", email)
    db.hset(f"user:{login}", "adress", adress)
    return True


def save_label(id, name, delivery_id, size):

    id = str(id)
    db.hset(f"label:{id}", "id", id)
    db.hset(f"label:{id}", "name", name)
    db.hset(f"label:{id}", "delivery_id", delivery_id)
    db.hset(f"label:{id}", "size", size)
    db.hset(f"label:{id}", "sender", session.get('login'))
    return True


def redirect(url, status=301):
    response = make_response('', status)
    response.headers['Location'] = url
    return response


def verify_user(login, password):
    password = password.encode()
    hashed = db.hget(f"user:{login}", "password")
    if not hashed:
        return False
    return checkpw(password, hashed)


@app.route('/')
def index():
    if session.get('login') is None:
        return render_template("index.html")

    return render_template('logged_index.html')


@app.route('/sender/register', methods=['GET'])
def registration_form():

    if session.get('login') is None:
        return render_template("registration.html")

    return redirect(url_for('index'))


@app.route('/sender/register', methods=['POST'])
def registration():
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    adress = request.form.get("adress")
    email = request.form.get("mail")
    login = request.form.get("login")
    password = request.form.get("password")
    password2 = request.form.get("password2")

    if not is_database_available():
        flash("Błąd połączenia z bazą danych")
        return redirect(url_for('registration_form'))

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
            flash(f"Użytkownik {login} istnieje")
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

    if session.get('login') is None:
        return render_template("login.html")

    return redirect(url_for('index'))


@app.route('/sender/login', methods=["POST"])
def login():
    login = request.form.get("login")
    password = request.form.get("password")

    if not is_database_available():
        flash("Błąd połączenia z bazą danych")
        return redirect(url_for('login_form'))

    if not login or not password:
        flash("Brak nazwy użytkownika lub hasła")
        return redirect(url_for('login_form'))
    if not verify_user(login,password):
        flash("Błędna nazwa użytkownika i/lub hasła")
        return redirect(url_for('login_form'))

    session["login"] = login
    session["logged-at"] = datetime.now()

    return redirect(url_for('dashboard'))


@app.route('/sender/dashboard')
def dashboard():

    if session.get('login') is None:
        flash("Najpierw musisz się zalogować")
        return redirect(url_for('login_form'))

    labels = {}

    for key in db.scan_iter("label:*"):
        if(db.hget(key,"sender").decode()==session.get('login')):
            labels[db.hget(key,"id").decode()]={
                "id":db.hget(key,"id").decode(),
                "name":db.hget(key,"name").decode(),
                "delivery_id":db.hget(key,"delivery_id").decode(),
                "size":db.hget(key,"size").decode()
            }

    delete_tokens = {}

    for label in labels:
        delete_tokens[label] = generate_delete_token(label, session.get('login')).decode()

    return render_template("dashboard.html", labels=labels.items(), haslabels=(len(labels)>0), delete_tokens=delete_tokens)


@app.route('/label/add',methods=['GET'])
def add_label_form():

    if session.get('login') is None:
        flash("Najpierw musisz się zalogować")
        return redirect(url_for('login_form'))

    return render_template("add_label.html")


@app.route('/label/add', methods=['POST'])
def add_label():
    name = request.form.get("name")
    delivery_id = request.form.get("delivary_id")
    size = request.form.get("size")
    label_id = uuid4()

    if not is_database_available():
        flash("Błąd połączenia z bazą danych")
        return redirect(url_for('add_label_form'))

    if not name:
        flash("Brak danych odbiorcy")
        return redirect(url_for('add_label_form'))

    if not delivery_id:
        flash("Brak id punktu odbioru")
        return redirect(url_for('add_label_form'))

    if not size:
        flash("Brak wybranego rozmiaru")
        return redirect(url_for('add_label_form'))

    if name and delivery_id and size:
        success = save_label(label_id,name,delivery_id,size)

    if not success:
        flash("Błąd tworzenia paczki")
        return redirect(url_for('add_label_form'))

    return redirect(url_for('dashboard'))


@app.route('/labels/<lid>', methods=["GET"])
def show_label(lid):

    if not db.hexists(f"label:{lid}","id"):
        flash("Taka etykieta nie istnieje")
        return redirect(url_for('index'))

    label = {
        "id": db.hget(f"label:{lid}", "id").decode(),
        "name": db.hget(f"label:{lid}", "name").decode(),
        "delivery_id": db.hget(f"label:{lid}", "delivery_id").decode(),
        "size": db.hget(f"label:{lid}", "size").decode()
    }

    return render_template("label.html", label_id=label['id'], name=label['name'], delivery=label['delivery_id'],size=label['size'])


@app.route('/label/delete/<lid>', methods=["GET"])
def delete_label(lid):
    token = request.args.get('token')

    if not db.hexists(f"label:{lid}","id"):
        flash("Taka etykieta nie istnieje")
        return redirect(url_for('index'))

    if token is None:
        flash("Nie masz dostępu do usunięcia etykiety")
        return redirect(url_for('index'))

    try:
        payload = decode(token, JWT_SECRET, algorithms=['HS256'], audience="label delete service")
    except jwt.InvalidTokenError:
        flash("Brak dostępu do usunięcia etykiety")
        return redirect(url_for('index'))

    if lid != payload.get('sub'):
        flash("Błąd autoryzacji")
        return redirect(url_for('index'))

    db.delete(f"label:{lid}")

    return redirect(url_for('dashboard'))


@app.route('/sender/logout')
def sender_logout():

    db.delete(f"session:{request.cookies.get('session')}")

    session.clear()

    return render_template("logout.html")


if __name__ == '__main__':
    app.run(threaded=True, port=5000)
