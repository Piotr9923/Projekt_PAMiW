from flask import Flask, request, make_response, session
from dotenv import load_dotenv
from flask import render_template, flash, url_for
from os import getenv
from datetime import datetime
import requests
import os
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

is_local = load_dotenv('.env')

if is_local is None:
    REDIS_HOST = os.environ.get("REDIS_HOST")
    REDIS_PASS = os.environ.get("REDIS_PASS")
    SECRET_KEY = os.environ.get("SECRET_KEY")
    WEBSERVICE_URL = os.environ.get("WEBSERVICE_URL")
    AUTH0_CALLBACK_URL = os.environ.get("AUTH0_CALLBACK_URL")
    AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
    AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")
    AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
    AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
    AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE")

else:
    REDIS_HOST = getenv("REDIS_HOST")
    REDIS_PASS = getenv("REDIS_PASS")
    SECRET_KEY = getenv("SECRET_KEY")
    WEBSERVICE_URL = getenv("WEBSERVICE_URL")
    AUTH0_CALLBACK_URL = getenv("AUTH0_CALLBACK_URL")
    AUTH0_CLIENT_ID = getenv("AUTH0_CLIENT_ID")
    AUTH0_CLIENT_SECRET = getenv("AUTH0_CLIENT_SECRET")
    AUTH0_DOMAIN = getenv("AUTH0_DOMAIN")
    AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
    AUTH0_AUDIENCE = getenv("AUTH0_AUDIENCE")

if WEBSERVICE_URL is None:
    WEBSERVICE_URL = "http://webservice:8000"

SESSION_TYPE = "filesystem"
SESSION_COOKIE_HTTPONLY = True

app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")


app.debug = False

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


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


@app.route('/sender/login/auth0', methods=["GET"])
def auth0_login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)


@app.route('/callback')
def callback_handling():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()
    session["JWT_PAYLOAD"] = userinfo

    user = {}
    user["login"] = userinfo["sub"]
    user["auth0"] = True
    user["name"] = userinfo["name"]
    user["email"] = userinfo["email"]

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
        session["auth0"] = True



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

        labels = json.get("_embedded")["labels"]

        for label in labels:
            label["canBeDeleted"] = True if label["status"] == "Utworzona" else False

        return render_template("dashboard.html", labels=labels, haslabels=(len(labels) > 0))

    else:
        errors = json.get("errors")
        for error in errors:
            flash(error)
        return redirect(url_for('dashboard'))


@app.route('/labels/add', methods=['GET'])
def add_label_form():
    if session.get('login') is None:
        flash("Najpierw musisz się zalogować")
        return redirect(url_for('login_form'))

    return render_template("add_label.html")


@app.route('/labels', methods=['POST'])
def add_label():
    new_label = {}
    new_label["name"] = request.form.get("name")
    new_label["delivery_id"] = request.form.get("delivary_id")
    new_label["size"] = request.form.get("size")

    response = webservice("POST", "/labels", new_label)

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


@app.route('/labels/<lid>', methods=["GET"])
def show_label(lid):

    if session.get('login') is None:
        flash("Najpierw musisz się zalogować")
        return redirect(url_for('login_form'))

    response = webservice("GET", "/labels/"+str(lid), {})

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


@app.route('/labels/<lid>', methods=["DELETE"])
def delete_label(lid):

    if session.get('login') is None:
        flash("Najpierw musisz się zalogować")
        return redirect(url_for('login_form'),status=400)

    response = webservice("DELETE", "/labels/"+str(lid), {})

    if response == "ERROR":
        session.clear()
        flash("Błąd łączności z usługą sieciową")
        return redirect(url_for('index'), status=500)

    if response.status_code == 440:
        return session_expired()

    json = response.json()

    if response.status_code != 200:
        errors = json.get("errors")
        for error in errors:
            flash(error)

    return redirect(url_for('dashboard'), status=200)


@app.route('/sender/logout')
def sender_logout():

    is_auth0 = False

    if session.get("auth0"):
        is_auth0 = True

    session.clear()

    if is_auth0:
        params = {'returnTo': url_for('sender_logout', _external=True), 'client_id': AUTH0_CLIENT_ID}
        return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

    return render_template("logout.html")


@app.route('/notifications')
def notifications():

    user_notifications = webservice("GET","/notifications",{})

    if user_notifications.status_code == 440:
        return "", 440

    if user_notifications.status_code == "ERROR" or (user_notifications.status_code != 200 and user_notifications.status_code != 204):
        return "", user_notifications.status_code

    if user_notifications.status_code == 204:
        return "", 204

    return user_notifications.json(), 200


if __name__ == '__main__':
    app.run(threaded=True, port=8000)
