from flask import Flask, request, make_response, session
from dotenv import load_dotenv
from flask import render_template, flash, url_for
from os import getenv
from datetime import datetime
from jwt import decode
import jwt
import requests
import os

is_local = load_dotenv('.env')

if is_local is None:
    REDIS_HOST = os.environ.get("REDIS_HOST")
    REDIS_PASS = os.environ.get("REDIS_PASS")
    SECRET_KEY = os.environ.get("SECRET_KEY")
    WEBSERVICE_URL = os.environ.get("WEBSERVICE_URL")

else:
    REDIS_HOST = getenv("REDIS_HOST")
    REDIS_PASS = getenv("REDIS_PASS")
    SECRET_KEY = getenv("SECRET_KEY")
    WEBSERVICE_URL = getenv("WEBSERVICE_URL")

if WEBSERVICE_URL is None:
    WEBSERVICE_URL = "http://webservice:8000"

SESSION_TYPE = "filesystem"
SESSION_COOKIE_HTTPONLY = True

app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")


app.debug = False


def session_expired():
    session.clear()
    flash("Twoja sesja wygasła. Zaloguj się ponownie.")
    return redirect(url_for("login_form"))


def webservice(method, url, json):
    token = ""
    if session.get("token"):
        token = session["token"]

    headers = {}
    headers["Authorization"] = token

    url = WEBSERVICE_URL + url

    try:
        if method == "GET":
            response = requests.get(url, json=json, headers=headers)
        elif method == "POST":
            response = requests.post(url, json=json, headers=headers)
        elif method == "DELETE":
            response = requests.delete(url, json=json, headers=headers)
        return response

    except Exception as e:
        print("Wystąpił błąd: "+str(e), flush=True)
        return "ERROR"


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

    if response == "ERROR":
        session.clear()
        flash("Błąd łączności z usługą sieciową")
        return redirect(url_for('index'))

    if response.status_code == 440:
        return session_expired()

    if response.status_code == 200:
        return redirect(url_for('login_form'))
    else:
        json = response.json()

        errors = json.get("errors")

        for error in errors:
            flash(error)
        return redirect(url_for('registration_form'))


@app.route('/sender/login', methods=["GET"])
def login_form():
    if session.get('login') is None:
        return render_template("login.html")

    return redirect(url_for('index'))


@app.route('/sender/login', methods=["POST"])
def login():
    user = {}

    user["login"] = request.form.get("login")
    user["password"] = request.form.get("password")

    response = webservice("POST", "/sender/login", user)

    if response == "ERROR":
        session.clear()
        flash("Błąd łączności z usługą sieciową")
        return redirect(url_for('index'))

    if response.status_code == 440:
        return session_expired()

    json = response.json()

    if response.status_code == 200:
        session["token"] = response.json().get("token")
        session["login"] = user.get("login")
        session["logged-at"] = datetime.now()
        session["session_expired"] = response.json().get("session_expired")
        return redirect(url_for('dashboard'))
    else:

        errors = json.get("errors")

        for error in errors:
            flash(error)
        return redirect(url_for('login_form'))


@app.route('/sender/dashboard')
def dashboard():
    if session.get('login') is None:
        flash("Najpierw musisz się zalogować")
        return redirect(url_for('login_form'))

    response = webservice("GET", "/sender/dashboard", {})

    if response == "ERROR":
        session.clear()
        flash("Błąd łączności z usługą sieciową")
        return redirect(url_for('index'))

    if response.status_code == 440:
        return session_expired()

    json = response.json()

    if response.status_code == 200:

        labels = json.get("labels")

        for label in labels:
            label["canBeDeleted"] = True if label["status"] == "Utworzona" else False

        return render_template("dashboard.html", labels=labels, haslabels=(len(labels) > 0))

    else:
        errors = json.get("errors")
        for error in errors:
            flash(error)
        return redirect(url_for('dashboard'))


@app.route('/label/add', methods=['GET'])
def add_label_form():
    if session.get('login') is None:
        flash("Najpierw musisz się zalogować")
        return redirect(url_for('login_form'))

    return render_template("add_label.html")


@app.route('/label/add', methods=['POST'])
def add_label():
    new_label = {}
    new_label["name"] = request.form.get("name")
    new_label["delivery_id"] = request.form.get("delivary_id")
    new_label["size"] = request.form.get("size")

    response = webservice("POST", "/label/add", new_label)

    if response == "ERROR":
        session.clear()
        flash("Błąd łączności z usługą sieciową")
        return redirect(url_for('index'))

    if response.status_code == 440:
        return session_expired()

    json = response.json()

    if response.status_code == 200:
        return redirect(url_for('dashboard'))
    else:
        errors = json.get("errors")

        for error in errors:
            flash(error)
        return redirect(url_for('add_label_form'))


@app.route('/label/<lid>/info', methods=["GET"])
def show_label(lid):

    if session.get('login') is None:
        flash("Najpierw musisz się zalogować")
        return redirect(url_for('login_form'))

    response = webservice("GET", "/label/"+str(lid)+"/info", {})

    if response == "ERROR":
        session.clear()
        flash("Błąd łączności z usługą sieciową")
        return redirect(url_for('index'))

    if response.status_code == 440:
        return session_expired()

    json = response.json()
    if response.status_code == 200:

        label = json.get("label")

        return render_template("label.html", label=label)

    else:
        errors = json.get("errors")
        for error in errors:
            flash(error)
        return redirect(url_for('dashboard'))


@app.route('/label/<lid>/delete', methods=["GET"])
def delete_label(lid):

    if session.get('login') is None:
        flash("Najpierw musisz się zalogować")
        return redirect(url_for('login_form'))

    response = webservice("DELETE", "/label/"+str(lid)+"/delete", {})

    if response == "ERROR":
        session.clear()
        flash("Błąd łączności z usługą sieciową")
        return redirect(url_for('index'))

    if response.status_code == 440:
        return session_expired()

    json = response.json()

    if response.status_code != 200:
        errors = json.get("errors")
        for error in errors:
            flash(error)

    return redirect(url_for('dashboard'))


@app.route('/sender/logout')
def sender_logout():

    session.clear()

    return render_template("logout.html")


if __name__ == '__main__':
    app.run(threaded=True, port=8000)
