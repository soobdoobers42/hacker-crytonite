from flask import Flask, render_template, redirect, request, url_for, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user

#For Honeypwn
import configparser
import logging
import threading
import sys
from socket import socket, timeout
 
 # -- Honeypwn code start --
def handle_client(client_socket, port, ip, remote_port):
    logger.info("Connection Received on port: %s from %s:%d " % (port, ip, remote_port))
    client_socket.settimeout(4)
    try:
        data = client_socket.recv(64)
        logger.info("Data received:%s from %s:%d - %s" % (port, ip, remote_port, data))
        client_socket.send("Access Denied.\n".encode('utf8'))
    except timeout:
        pass
    except ConnectionResetError as e:
        logger.error("Connection Reset Error occurred")
    client_socket.close()

def start_new_listener_thread(port):
    listener = socket()
    listener.bind((BIND_IP, int(port)))
    listener.listen(5)

    while True:
        client, addr = listener.accept()
        client_handler = threading.Thread(target=handle_client, args=(client, port, addr[0], addr[1]))
        client_handler.start()

def setup_logging():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname) -8s %(message)s', datefmt='%Y-%m-%d %H:%M:%s', filename=logfile, filemode='w')
    logger = logging.getLogger('')
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    return logger


 # -- Honeypwn code end --

# Create a flask application
app = Flask(__name__)
 
# Tells flask-sqlalchemy what database to connect to
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
# Enter a secret key
app.config["SECRET_KEY"] = "ENTER YOUR SECRET KEY"
# Initialize flask-sqlalchemy extension
db = SQLAlchemy()
 
# LoginManager is needed for our application 
# to be able to log in and out users
login_manager = LoginManager()
login_manager.init_app(app)

# Create user model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True,
                         nullable=False)
    password = db.Column(db.String(250),
                         nullable=False)
 
 
# Initialize app with extension
db.init_app(app)
# Create database within app context
 
with app.app_context():
    db.create_all()

# Creates a user loader callback that returns the user object given an id
@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)

@app.route('/register', methods=["GET", "POST"])
def register():
  # If the user made a POST request, create a new user
    if request.method == "POST":
        user = Users(username=request.form.get("username"),
                     password=request.form.get("password"))
        # Add the user to the database
        db.session.add(user)
        # Commit the changes made
        db.session.commit()
        # Once user account created, redirect them
        # to login route (created later on)
        return redirect(url_for("login"))
    # Renders sign_up template if user made a GET request
    return render_template("sign_up.html")

#purposefully induced sql injection query here
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Introduce vulnerability by concatenating inputs directly into the SQL query
        query = f"SELECT * FROM Users WHERE username='{username}' AND password='{password}'"
        
        cursor = db.engine.raw_connection().cursor()
        cursor.execute(query)
        users = cursor.fetchall()

        # Print debug information
        print("SQL Query:", query)
        print("Result:", users)

        if users:
            # Pass users data to home page upon successful injection
            return redirect(url_for("home", users=users))
        else:
            # User not found, display error message
            return "Invalid username or password"
    return render_template("login.html")

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))

#purposefully induce users into home html
@app.route("/")
def home():
    # Retrieve users data passed from login logic
    users = request.args.get("users", None)    

    # Render home.html and pass the users data
    return render_template("home.html", users=users)


if __name__ == "__main__":
    app.run()
    BIND_IP = '127.0.0.1'
    config_filepath = 'honeypwned.ini'

    config = configparser.ConfigParser()
    config.read(config_filepath)

    ports = config.get('default', 'ports', raw=True, fallback="22,80,443,8080,8888,9999")
    logfile = config.get('default', 'logfile', raw=True, fallback="honeypwned.log")
    logger = setup_logging()

