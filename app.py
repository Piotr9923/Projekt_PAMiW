from flask import Flask, render_template

app = Flask(__name__,static_url_path='/static')

app.debug = False

@app.route('/sender/sign-up', methods=["POST","GET"])
def registration():
    return render_template("registration.html")


@app.route('/')
def index():
    #return render_template("index.html")
    return "Hello World"

if __name__ == '__main__':
    app.run(threaded=True, port=5000)
