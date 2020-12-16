from flask import Flask, request, make_response, session
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
import requests

load_dotenv('.env')

REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
WEBSERVICE_URL = getenv("WEBSERVICE_URL")

if WEBSERVICE_URL is None:
    WEBSERVICE_URL = "http://127.0.0.1:5000"

SESSION_TYPE = "filesystem"
SESSION_COOKIE_HTTPONLY = True

app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")


app.debug = False


def webservice(method, url, json):
    token = ""
    if session.get("token"):
        token = session["token"]

    headers = {}
    headers["Authorization"] = token

    url = WEBSERVICE_URL + url
    try:
        if method == "GET":
            return requests.get(url, json=json, headers=headers)
        elif method == "POST":
            return requests.post(url, json=json, headers=headers)
        elif method == "DELETE":
            return requests.delete(url, json=json, headers=headers)
    except Exception as e:
        print("Wystąpił błąd: "+str(e))
        flash("Błąd łączności z usługą sieciową")


def redirect(url, status=301):
    response = make_response('', status)
    response.headers['Location'] = url
    return response


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
    new_user = {}

    new_user["firstname"] = request.form.get("firstname")
    new_user["lastname"] = request.form.get("lastname")
    new_user["adress"] = request.form.get("adress")
    new_user["mail"] = request.form.get("mail")
    new_user["login"] = request.form.get("login")
    new_user["password"] = request.form.get("password")
    new_user["password2"] = request.form.get("password2")

    response = webservice("POST", "/sender/register", new_user)

    json = response.json()

    errors = json.get("errors")

    if errors:
        for error in errors:
            flash(error)
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
    if not verify_user(login, password):
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
        print("KEY + ")
        print(key)

        if (db.hget(key, "sender") == session.get('login')):
            labels[db.hget(key, "id").decode()] = {
                "id": db.hget(key, "id").decode(),
                "name": db.hget(key, "name").decode(),
                "delivery_id": db.hget(key, "delivery_id").decode(),
                "size": db.hget(key, "size").decode()
            }

    delete_tokens = {}

    for label in labels:
        delete_tokens[label] = generate_delete_token(label, session.get('login')).decode()

    return render_template("dashboard.html", labels=labels.items(), haslabels=(len(labels) > 0),
                           delete_tokens=delete_tokens)


@app.route('/label/add', methods=['GET'])
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
        success = save_label(label_id, name, delivery_id, size)

    if not success:
        flash("Błąd tworzenia paczki")
        return redirect(url_for('add_label_form'))

    return redirect(url_for('dashboard'))


@app.route('/labels/<lid>', methods=["GET"])
def show_label(lid):
    if not db.hexists(f"label:{lid}", "id"):
        flash("Taka etykieta nie istnieje")
        return redirect(url_for('index'))

    label = {
        "id": db.hget(f"label:{lid}", "id").decode(),
        "name": db.hget(f"label:{lid}", "name").decode(),
        "delivery_id": db.hget(f"label:{lid}", "delivery_id").decode(),
        "size": db.hget(f"label:{lid}", "size").decode()
    }

    return render_template("label.html", label_id=label['id'], name=label['name'], delivery=label['delivery_id'],
                           size=label['size'])


@app.route('/label/delete/<lid>', methods=["GET"])
def delete_label(lid):
    token = request.args.get('token')

    if not db.hexists(f"label:{lid}", "id"):
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
    app.run(threaded=True, port=8000)
