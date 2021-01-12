from flask import Flask, request, g
from dotenv import load_dotenv
from os import getenv
from bcrypt import hashpw, gensalt, checkpw
from redis import StrictRedis
from datetime import datetime, timedelta
from uuid import uuid4
from jwt import encode, decode, ExpiredSignatureError, get_unverified_header
from redis.exceptions import ConnectionError
from flask_hal import HAL
from flask_hal.document import Document, Embedded
from flask_hal.link import Link
import os
import requests
from jwt.jwks_client import PyJWKClient

app = Flask(__name__)
HAL(app)
is_local = load_dotenv('.env')


if is_local is None:
    REDIS_HOST = os.environ.get("REDIS_HOST")
    REDIS_PASS = os.environ.get("REDIS_PASS")
    SECRET_KEY = os.environ.get("SECRET_KEY")
    JWT_SECRET = os.environ.get("JWT_SECRET")
    AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
    AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE")
    AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")


else:
    REDIS_HOST = getenv("REDIS_HOST")
    REDIS_PASS = getenv("REDIS_PASS")
    SECRET_KEY = getenv("SECRET_KEY")
    JWT_SECRET = getenv("JWT_SECRET")
    AUTH0_DOMAIN = getenv("AUTH0_DOMAIN")
    AUTH0_AUDIENCE = getenv("AUTH0_AUDIENCE")
    AUTH0_CLIENT_ID = getenv("AUTH0_CLIENT_ID")

if REDIS_HOST:
    db = StrictRedis(REDIS_HOST, db=25, password=REDIS_PASS, port=6379)
else:
    db = StrictRedis(host='redis', port=6379, db=0)

SESSION_TYPE = "redis"
SESSION_REDIS = db
SESSION_COOKIE_HTTPONLY = True
JWT_TIME = 300
app.config.from_object(__name__)
app.secret_key = SECRET_KEY

app.debug = False


@app.before_request
def before():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token is not None:
        try:
            g.authorization = decode(token, str(JWT_SECRET), algorithms=["HS256"])
        except ExpiredSignatureError:
            links = [Link("login", "sender/login")]
            document = Document(links=links)
            return document.to_json(), 440

        except Exception as e:
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
    id = str(id)
    db.hset(f"label:{id}", "id", id)
    db.hset(f"label:{id}", "name", name)
    db.hset(f"label:{id}", "delivery_id", delivery_id)
    db.hset(f"label:{id}", "size", size)
    db.hset(f"label:{id}", "sender", g.authorization.get("usr"))
    return True


def create_package(label):

    id = label['id']
    name = label['name']
    delivery_id = label['delivery_id']
    size = label['size']
    sender = label['sender']
    status = "W drodze"

    db.hset(f"package:{id}", "id", id)
    db.hset(f"package:{id}", "name", name)
    db.hset(f"package:{id}", "delivery_id", delivery_id)
    db.hset(f"package:{id}", "size", size)
    db.hset(f"package:{id}", "sender", sender)
    db.hset(f"package:{id}", "status", status)
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

    links.append(Link("login", "/sender/login", type="POST"))
    links.append(Link("registration", "/sender/register", type="POST"))
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
    auth0 = form_values.get("auth0")

    links = []
    errors = []
    links.append(Link("login", "/sender/login", type="POST"))
    links.append(Link("registration", "/sender/register", type="POST"))

    if not is_database_available():
        errors.append("Błąd połączenia z bazą danych")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 500

    if auth0 is None:
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
    links.append(Link("labels", "/sender/dashboard", type="GET"))
    links.append(Link("label:new", "/labels", type="POST"))

    payload = {
        "exp": datetime.utcnow() + timedelta(seconds=JWT_TIME),
        "usr": login
    }
    token = encode(payload, JWT_SECRET, algorithm='HS256')
    data["status"] = "logged"
    data["token"] = token
    document = Document(data=data, links=links)
    return document.to_json(), 200


@app.route('/sender/dashboard', methods=["GET"])
def dashboard():
    data = {}
    links = []
    labels = []
    errors = []

    login = g.authorization.get("usr")
    links.append(Link("find", "/labels/{id}", templated=True))
    links.append(Link("label:new", "/labels", type="POST"))

    if login is None:
        errors.append("Brak autoryzacji")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    for key in db.scan_iter("label:*"):
        if db.hget(key, "sender").decode() == login:

            status = db.hget(f"package:{db.hget(key, 'id').decode()}", "status")
            if status is None:
                status = "Utworzona"
            else:
                status = status.decode()
            label = {}
            label = {
                "id": db.hget(key, "id").decode(),
                "name": db.hget(key, "name").decode(),
                "delivery_id": db.hget(key, "delivery_id").decode(),
                "size": db.hget(key, "size").decode(),
                "status": status
            }

            labels.append(label)

    items = []
    for label in labels:
        item_links = []
        link_info = Link("info", "/labels/" + label["id"], type="GET")
        item_links.append(link_info)
        if label["status"] == "Utworzona":
            link_delete = Link("delete", "/labels/" + label["id"], type="DELETE")
            item_links.append(link_delete)
        items.append(Embedded(data=label, links=item_links))

    document = Document(embedded={'labels' : Embedded(data=items)}, links=links)
    return document.to_json(), 200


@app.route('/labels', methods=['POST'])
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
    links.append(Link("labels", "/sender/dashboard", type="GET"))

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
    links.append(Link("labels", "/sender/dashboard", type="GET"))
    links.append(Link("delete", "/labels/" + str(lid), type="DELETE"))
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
        status = "Utworzona"
    else:
        status = status.decode()

    label = {
        "id": db.hget(f"label:{lid}", "id").decode(),
        "name": db.hget(f"label:{lid}", "name").decode(),
        "delivery_id": db.hget(f"label:{lid}", "delivery_id").decode(),
        "size": db.hget(f"label:{lid}", "size").decode(),
        "status": status
    }

    labels["label"] = label

    document = Document(data=labels, links=links)
    return document.to_json(), 200


@app.route('/labels/<lid>', methods=["DELETE"])
def delete_label(lid):
    errors = []
    links = []
    links.append(Link("labels", "/sender/dashboard", type="GET"))
    links.append(Link("label:new", "/labels", type="POST"))

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


@app.route('/labels', methods=["GET"])
def get_labels():
    data = {}
    links = []
    labels = []
    errors = []

    is_not_send = request.headers.get('is_not_send')

    if is_not_send == "True":
        is_not_send = True
    else:
        is_not_send = False

    login = g.authorization.get("usr")

    if login is None or login != "Courier":
        errors.append("Brak autoryzacji")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    for key in db.scan_iter("label:*"):
        status = db.hget(f"package:{db.hget(key, 'id').decode()}", "status")
        if status is None:
            status = "Utworzona"
        else:
            status = status.decode()
        label = {}
        label = {
            "id": db.hget(key, "id").decode(),
            "name": db.hget(key, "name").decode(),
            "delivery_id": db.hget(key, "delivery_id").decode(),
            "size": db.hget(key, "size").decode(),
            "status": status,
            "sender": db.hget(key, "sender").decode()
        }
        if is_not_send:
            if(status == "Utworzona"):
                labels.append(label)
        else:
            labels.append(label)

    for label in labels:
        links.append(Link("label:" + (label["id"]), "/labels/" + label["id"]))

    data["labels"] = labels

    links.append(Link("find", "/label/{id}", templated=True))

    document = Document(data=data, links=links)
    return document.to_json(), 200


@app.route('/packages', methods=["GET"])
def get_package():
    data = {}
    links = []
    packages = []
    errors = []

    login = g.authorization.get("usr")

    if login is None or login != "Courier":
        errors.append("Brak autoryzacji")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    for key in db.scan_iter("package:*"):
        status = db.hget(f"package:{db.hget(key, 'id').decode()}", "status")
        if status is None:
            status = "Utworzona"
        else:
            status = status.decode()
        package = {}
        package = {
            "id": db.hget(key, "id").decode(),
            "name": db.hget(key, "name").decode(),
            "delivery_id": db.hget(key, "delivery_id").decode(),
            "size": db.hget(key, "size").decode(),
            "status": status,
            "sender": db.hget(key, "sender").decode()
        }
        packages.append(package)

    for package in packages:
        links.append(Link("label:" + (package["id"]), "/labels/" + package["id"]))

    data["packages"] = packages

    links.append(Link("package:new", "/pacakges", type="POST"))
    links.append(Link("find", "/pacakges/{id}", templated=True, type="GET"))

    document = Document(data=data, links=links)
    return document.to_json(), 200


@app.route('/packages', methods=["POST"])
def add_package():
    links = []
    errors = []

    login = g.authorization.get("usr")

    if login is None or login != "Courier":
        errors.append("Brak autoryzacji")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    label_id = request.json['label_id']

    if label_id is None:
        errors.append("Brak etykiety")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 400

    links = []
    links.append(Link("packages", "/pacakges", type="GET"))
    links.append(Link("find", "/pacakges/{id}", templated=True, type="GET"))

    if not is_database_available():
        errors.append("Błąd połączenia z bazą danych")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 500

    if not db.hexists(f"label:{label_id}", "id"):
        errors.append("Taka etykieta nie istnieje")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 404

    status = db.hget(f"package:{label_id}", "status")
    if status is not None:
        errors.append("Istnieje paczka utworzona z tej etykiety")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 404

    label = {
        "id": db.hget(f"label:{label_id}", "id").decode(),
        "name": db.hget(f"label:{label_id}", "name").decode(),
        "delivery_id": db.hget(f"label:{label_id}", "delivery_id").decode(),
        "size": db.hget(f"label:{label_id}", "size").decode(),
        "sender": db.hget(f"label:{label_id}", "sender").decode()
    }

    success = create_package(label)

    if not success:
        errors.append("Błąd tworzenia etykiety")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 500
    document = Document(links=links)
    return document.to_json(), 200


    document = Document(links=links)
    return document.to_json(), 200


@app.route('/packages/<pid>', methods=["PUT"])
def update_package(pid):
    errors = []
    links = []
    labels = {}
    links.append(Link("packages", "/pacakges", type="GET"))
    links.append(Link("package:new", "/pacakges", type="POST"))
    links.append(Link("find", "/pacakges/{id}", templated=True, type="GET"))

    login = g.authorization.get("usr")

    if login is None or login != "Courier":
        errors.append("Brak autoryzacji")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 401

    package_id = request.json['package_id']

    if package_id is None:
        errors.append("Brak Id paczki")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 400

    if not is_database_available():
        errors.append("Błąd połączenia z bazą danych")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 500

    if not db.hexists(f"package:{package_id}", "id"):
        errors.append("Taka paczka nie istnieje")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 404

    status = db.hget(f"package:{package_id}", "status").decode()
    if status == "Odebrana":
        errors.append("Ta paczka została odebrana. Nie możesz zmienić jej statusu")
        document = Document(data={"errors": errors}, links=links)
        return document.to_json(), 404

    if status == "W drodze":
        db.hset(f"package:{package_id}", "status", "Dostarczona")
    elif status == "Dostarczona":
        db.hset(f"package:{package_id}", "status", "Odebrana")

    document = Document(data=labels, links=links)
    return document.to_json(), 200


@app.route('/courier/token', methods=["GET"])
def generate_token():
    access_token = request.headers.get("Access_Token")
    id_token = request.headers.get("ID_Token")

    response = requests.get(AUTH0_DOMAIN+"/.well-known/jwks.json")

    if response.status_code != 200:
        document = Document(data={"error": "Wystąpił błąd. Spróbuj ponownie później."})
        return document.to_json(), 400

    try:
        kid = get_unverified_header(access_token)["kid"]
    except Exception:
        document = Document(data={"error": "Wystąpił błąd. Spróbuj ponownie później."})
        return document.to_json(), 400

    url = AUTH0_DOMAIN+"/.well-known/jwks.json"

    jwks_client = PyJWKClient(url)

    signing_key = jwks_client.get_signing_key_from_jwt(access_token)

    try:
        data = decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUTH0_AUDIENCE
        )
    except Exception as e:
        document = Document(data={"error": "Brak autoryzacji. Spróbuj ponownie później."})
        return document.to_json(), 401

    try:
        data = decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUTH0_CLIENT_ID
        )
    except Exception as e:
        document = Document(data={"error": "Brak autoryzacji. Spróbuj ponownie później."})
        return document.to_json(), 401

    payload = {
        "exp": datetime.utcnow() + timedelta(days=365),
        "usr": "Courier",
        "name": data["name"],
        "sub": data["sub"]
    }
    token = encode(payload, JWT_SECRET, algorithm='HS256')

    document = Document(data={"token":token})
    return document.to_json(), 200


if __name__ == '__main__':
    app.run(threaded=True, port=5000)
