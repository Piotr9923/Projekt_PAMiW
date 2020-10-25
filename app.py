from flask import Flask, render_template

app = Flask(__name__)

app.debug = False


@app.route('/')
def index():
    return render_template("index.html")


app.run()

