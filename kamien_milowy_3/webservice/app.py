from flask import Flask, request, make_response, g
from dotenv import load_dotenv
from flask import render_template, flash, url_for
from os import getenv
from bcrypt import hashpw, gensalt, checkpw
from redis import StrictRedis
from datetime import datetime, timedelta
from uuid import uuid4
from jwt import encode, decode, ExpiredSignatureError
from redis.exceptions import ConnectionError
import jwt
from flask_hal import HAL
from flask_hal.document import Document, Embedded
from flask_hal.link import Link
import json

app = Flask(__name__)
HAL(app)
load_dotenv('.env')

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
JWT_TIME = 600
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")

app.debug = False


@app.before_request
def before():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token is not None:
        try:
            g.authorization = decode(token, str(JWT_SECRET), algorithms=["HS256"])
            print("Authorized " + str(g.authorization))
        except ExpiredSignatureError:
            links = [Link("login", "sender/login")]
            document = Document(links=links)
            return document.to_json(), 440

        except Exception as e:
            print("Unauthorized " + str(e))
            g.authorization = {}
    else:
        g.authorization = {}


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
    db.hset(f"user:{login}", "password", hashed)
    db.hset(f"user:{login}", "firstname", firstname)
    db.hset(f"user:{login}", "lastname", lastname)
    db.hset(f"user:{login}", "email", email)
    db.hset(f"user:{login}", "adress", adress)
    return True


def save_label(id, name, delivery_id, size):
    print(g.authorization.get("usr"))
    id = str(id)
    db.hset(f"label:{id}", "id", id)
    db.hset(f"label:{id}", "name", name)
    db.hset(f"label:{id}", "delivery_id", delivery_id)
    db.hset(f"label:{id}", "size", size)
    db.hset(f"label:{id}", "sender", g.authorization.get("usr"))
    return True


def verify_user(login, password):
    password = password.encode()
    hashed = db.hget(f"user:{login}", "password")
    if not hashed:
        return False
    return checkpw(password, hashed)


@app.route('/')
def index():
    links = []
    if g.authorization.get("usr") is None:
        links.append(Link("login", "/sender/login"))
        links.append(Link("register", "/sender/register"))
        document = Document(data={}, links=links)
        return document.to_json(), 200

    links.append(Link("dashboard", "/sender/dashboard"))
    links.append(Link("add_label", "/label/add"))
    document = Document(data={}, links=links)
    return document.to_json(), 200


@app.route('/sender/register', methods=['POST'])
def registration():
    form_values = request.json
    errors = []
    if form_values is None:
        return {"error": "Brak JSON"}

    firstname = form_values.get("firstname")
    lastname = form_values.get("lastname")
    adress = form_values.get("adress")
    email = form_values.get("mail")
    login = form_values.get("login")
    password = form_values.get("password")
    password2 = form_values.get("password2")

    links = []
    links.append(Link("login", "/sender/login"))
    links.append(Link("register", "/sender/register"))

    if not is_database_available():
        errors.append("Błąd połączenia z bazą danych")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 500

    if not firstname:
        errors.append("Brak imienia")
    if not lastname:
        errors.append("Brak nazwiska")
    if not adress:
        errors.append("Brak adresu")
    if not email:
        errors.append("Brak maila")
    if not login:
        errors.append("Brak loginu")
    if not password:
        errors.append("Brak hasła")
    if password != password2:
        errors.append("Hasła nie są takie same")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 400

    if email and login and password and firstname and lastname and adress:
        if is_user(login):
            errors.append("Taka nazwa użytkownika istnieje")
            document = Document(data={"errors": errors}, links=links)
            return document.to_json(), 400
    else:
        print("ZWRACAM ERRORS: " + str(errors))
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 400

    success = save_user(firstname, lastname, login, email, password, adress)
    if not success:
        errors.append("Wystąpił błąd podczas rejestracji. Spróbuj później")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 500

    document = Document(links=links)
    return document.to_json(), 200


@app.route('/sender/login', methods=["POST"])
def login():
    form_values = request.json
    if form_values is None:
        return {"error": "Brak JSON"}

    login = form_values.get("login")
    password = form_values.get("password")

    links = []
    errors = []
    links.append(Link("login", "/sender/login"))
    links.append(Link("register", "/sender/register"))

    if not is_database_available():
        errors.append("Błąd połączenia z bazą danych")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 500

    if not login or not password:
        errors.append("Brak loginu lub hasła")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 400

    if not verify_user(login, password):
        errors.append("Błędny login lub hasło")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 400

    links = []
    data = {}
    links.append(Link("dashboard", "/sender/dashboard"))
    links.append(Link("label:add", "/label/add"))
    links.append(Link("logout", "/sender/logout"))
    payload = {
        "exp": datetime.utcnow() + timedelta(seconds=JWT_TIME),
        "usr": login
    }
    token = encode(payload, JWT_SECRET, algorithm='HS256')
    data["status"] = "logged"
    data["token"] = token.decode()
    document = Document(data=data, links=links)
    return document.to_json(), 200


@app.route('/sender/dashboard', methods=["GET"])
def dashboard():
    data = {}
    links = []
    labels = []
    errors = []

    login = g.authorization.get("usr")

    if login is None:
        errors.append("Brak autoryzacji")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    for key in db.scan_iter("label:*"):
        if db.hget(key, "sender").decode() == login:

            status = db.hget(f"package:{db.hget(key, 'id').decode()}", "status")
            if status is None:
                status = "Nadana"
            label = {}
            label = {
                "id": db.hget(key, "id").decode(),
                "name": db.hget(key, "name").decode(),
                "delivery_id": db.hget(key, "delivery_id").decode(),
                "size": db.hget(key, "size").decode(),
                "status": status
            }
            labels.append(label)

    for label in labels:
        links.append(Link("label:" + (label["id"]), "/labels/" + label["id"]))

    links.append(Link("label:add", "/label/add"))
    links.append(Link("label:{la}", "/sender/logout"))

    data["labels"] = labels
    data["login"] = login
    document = Document(data=data, links=links)
    return document.to_json(), 200


@app.route('/label/add', methods=['POST'])
def add_label():
    form_values = request.json

    errors = []

    if g.authorization is None:
        errors.append("Brak autoryzacji")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    if form_values is None:
        errors.append("Brak pliku JSON")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 400
    links = []
    links.append(Link("dashboard", "/sender/dashboard"))
    links.append(Link("label:add", "/label/add"))
    links.append(Link("label:{la}", "/sender/logout"))

    name = form_values.get("name")
    delivery_id = form_values.get("delivery_id")
    size = form_values.get("size")
    label_id = uuid4()
    if not is_database_available():
        errors.append("Błąd połączenia z bazą danych")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 500
    if not name:
        errors.append("Brak nazwy odbiorcy")

    if not delivery_id:
        errors.append("Brak id punktu odbioru")

    if not size:
        errors.append("Brak rozmiaru")
    if len(errors) > 0:
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 400
    if name and delivery_id and size:
        success = save_label(label_id, name, delivery_id, size)
    if not success:
        errors.append("Błąd tworzenia etykiety")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 500
    document = Document(links=links)
    return document.to_json(), 200


@app.route('/labels/<lid>', methods=["GET"])
def show_label(lid):
    errors = []
    links = []
    labels = {}
    links.append(Link("dashboard", "/sender/dashboard"))
    links.append(Link("label:add", "/label/add"))

    login = g.authorization.get("usr")

    if login is None:
        errors.append("Musisz się zalogować")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    if not db.hexists(f"label:{lid}", "id"):
        errors.append("Taka etykieta nie istnieje")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 404

    if login != db.hget(f"label:{lid}", "sender").decode():
        errors.append("To nie Twoja etykieta")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    status = db.hget(f"package:{lid}", "status")
    if status is None:
        status = "Nadana"

    label = {
        "id": db.hget(f"label:{lid}", "id").decode(),
        "name": db.hget(f"label:{lid}", "name").decode(),
        "delivery_id": db.hget(f"label:{lid}", "delivery_id").decode(),
        "size": db.hget(f"label:{lid}", "size").decode(),
        "status": status
    }

    labels["label"] = label

    print(labels)

    document = Document(data=labels, links=links)
    return document.to_json(), 200


@app.route('/label/delete/<lid>', methods=["DELETE"])
def delete_label(lid):
    errors = []
    links = []
    links.append(Link("dashboard", "/sender/dashboard"))
    links.append(Link("label:add", "/label/add"))
    links.append(Link("label:{la}", "/sender/logout"))

    login = g.authorization.get("usr")

    if login is None:
        errors.append("Musisz się zalogować")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    if not db.hexists(f"label:{lid}", "id"):
        errors.append("Taka etykieta nie istnieje")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 400

    if login != db.hget(f"label:{lid}", "sender").decode():
        errors.append("To nie Twoja etykieta")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    if db.hexists(f"package:{lid}", "id"):
        errors.append("Nie możesz usunąć tej etykiety")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    db.delete(f"label:{lid}")

    document = Document(links=links)
    return document.to_json(), 200


if __name__ == '__main__':
    app.run(threaded=True, port=5000)