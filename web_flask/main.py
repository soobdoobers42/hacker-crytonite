from flask import Flask, render_template, redirect, request, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user
 
# Firebase
from firebase import firebase
from firebase_admin import credentials, db, initialize_app
import firebase_admin

cred = credentials.Certificate('key.json')

firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://honeypwn-f7521-default-rtdb.firebaseio.com/',
    'databaseAuthVariableOverride': None
})


# As an admin, the app has access to read and write all data, regradless of Security Rules
ref = db.reference('/users')
print(ref.get())

# Create a flask application
app = Flask(__name__)

 
 # Initialize Firestore DB
cred = credentials.Certificate('key.json')

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password=request.form.get("password")


        ref.push().set({
                "username" : username,
                "password" : password
        })

        
        return redirect(url_for("login"))
     
    return render_template("sign_up.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    return render_template("login.html")

# @app.route("/logout")
# def logout():
#     return redirect(url_for("home"))

@app.route("/")
def home():
    # Render home.html on "/" route
    # return str(result)
    return render_template("home.html")

if __name__ == "__main__":
    app.run()

