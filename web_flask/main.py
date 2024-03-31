from flask import Flask, render_template, redirect, request, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user
 
# Firebase
from firebase import firebase
from firebase_admin import credentials, firestore, initialize_app

firebase =  firebase.FirebaseApplication('https://honeypwn-f7521-default-rtdb.firebaseio.com/', None)

# Create a flask application
app = Flask(__name__)
 
 # Initialize Firestore DB
cred = credentials.Certificate('key.json')
default_app = initialize_app(cred)

# @app.route('/register', methods=["GET", "POST"])
# def register():

#     return render_template("sign_up.html")

# @app.route("/login", methods=["GET", "POST"])
# def login():

#     return render_template("login.html")

# @app.route("/logout")
# def logout():
#     return redirect(url_for("home"))

@app.route("/")
def home():
    # Render home.html on "/" route
    result = firebase.get('/users', None)
    # return str(result)
    return render_template("home.html", results = result)

if __name__ == "__main__":
    app.run()

