from flask import Flask, render_template, redirect, request, url_for, g, has_request_context, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user
import configparser
import logging
import threading
import sys
from socket import socket, timeout
import os
import paramiko
import datetime
import subprocess
 
 # Global Variable
BIND_IP = '0.0.0.0'
config_filepath = 'honeypwned.ini'
ssh_port = 22  # Default SSH port

def handle_client(client_socket, port, ip, remote_port):
    current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S%f")[:-3]
    logger.info("[%s] Connection Received on port: [%s] from [%s:%d] " % (current_time, port, ip, remote_port))
    client_socket.settimeout(4)
    try:
        data = client_socket.recv(64)
        logger.info("[%s] Data received on port: [%s] from [%s:%d] - [%s]" % (current_time, port, ip, remote_port, data))
        client_socket.send("Access Denied.\n".encode('utf8'))
    except timeout:
        pass
    except ConnectionResetError as e:
        logger.error("[%s] Connection Reset Error occurred" % current_time)
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
    logging.basicConfig(level=logging.DEBUG, format='%(message)s', datefmt='%Y-%m-%d %H:%M:%S', filename=logfile, filemode='a')
    logger = logging.getLogger('')
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    return logger

def get_files():
    # Specify the directory where your files are stored
    directory = 'static'
    # Get the list of files in the directory
    files = os.listdir(directory)
    # Return the list of files
    return files
 
def start_flask_server(logger):
    # Create a flask application
    app = Flask(__name__)
    
    current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S%f")[:-3]
    # Tells flask-sqlalchemy what database to connect to
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
    # Enter a secret key
    app.config["SECRET_KEY"] = "ENTER YOUR SECRET KEY"

    # Initialize flask-sqlalchemy extension
    db = SQLAlchemy(app)

    # Establishing DB connection    
    # engine =db.create_engine("sqlite:///db.sqlite")
    # conn = engine.connect()
    
    # LoginManager is needed for our application 
    # to be able to log in and out users
    login_manager = LoginManager()
    login_manager.init_app(app)

    # Custom logging formatter
    class RequestFormatter(logging.Formatter):
        def format(self, record):
            if has_request_context():
                url = request.url
                remote = request.remote_addr
            else:
                url = 'Unknown'
                remote = 'Unknown'
            record.url = url
            record.remote = remote
            return super().format(record)

    # Remove previous StreamHandler to avoid duplicate logs
    for handler in logger.handlers[:]:
        if isinstance(handler, logging.StreamHandler):
            logger.removeHandler(handler)

    # Add a file handler to write to the log file
    file_handler = logging.FileHandler(logfile)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(RequestFormatter("%(message)s"))
    logger.addHandler(file_handler)

    # Attach custom formatter to logger for console output
    logFormatter = RequestFormatter("%(message)s")
    ch = logging.StreamHandler()
    ch.setFormatter(logFormatter)
    logger.addHandler(ch)

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

    # Not needed for demo
    # @app.route('/register', methods=["GET", "POST"])
    # def register():
    #     logger.info("[%s] Connection Received on port: [80] from [%s] - [Accessing register page]" % (current_time, request.remote_addr))
    #     # Define the directory path
    #     directory = os.path.join(app.root_path, 'templates')
    #     # Get the list of files in the directory
    #     files = os.listdir(directory)
    # # If the user made a POST request, create a new user
    #     if request.method == "POST":
    #         user = Users(username=request.form.get("username"),
    #                     password=request.form.get("password"))
    #         # Add the user to the database
    #         db.session.add(user)
    #         # Commit the changes made
    #         db.session.commit()
    #         # Once user account created, redirect them
    #         # to login route (created later on)
    #         return redirect(url_for("login"))
    #     # Renders sign_up template if user made a GET request
    #     return render_template("sign_up.html", files=files)

    #purposefully induced sql injection query here
    @app.route("/login", methods=["GET", "POST"])
    def login():
        logger.info("[%s] Connection Received on port: [80] from [%s] - [Accessing Login page]" % (current_time, request.remote_addr))
        # Define the directory path
        directory = os.path.join(app.root_path, 'templates')
        # Get the list of files in the directory
        files = os.listdir(directory)
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            with db.session() as session:
                # Introduce vulnerability by concatenating inputs directly into the SQL query
                query = f"SELECT * FROM Users WHERE username=:username AND password=:password"
                result = session.execute(query, {'username': username, 'password': password})
                user = result.fetchone()
                
            # output = conn.execute(query)
    
            # users = output.fetchall()

            # Print debug information
            print("SQL Query:", query)
            print("Result:", user)

            if user:
                # Pass users data to home page upon successful injection
                return redirect(url_for("home", users=user))
            else:
                # User not found, display error message
                return "Invalid username or password"
        return render_template("login.html", files = files)

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
        app.run(host='0.0.0.0', port=80)

def generate_or_read_ssh_key():
    key_folder = 'Files'
    key_path = os.path.join(key_folder, 'ssh_key')
    if not os.path.exists(key_path):
        # Generate SSH key if not exists
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_path)
    else:
        # Read SSH key
        key = paramiko.RSAKey(filename=key_path)
    return key

class SSHServer(paramiko.ServerInterface):
    def __init__(self, addr0, addr1):
        super().__init__()
        self.addr0 = addr0
        self.addr1 = addr1
    def check_auth_password(self, username: str, password: str) -> int:
        current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S%f")[:-3]
        logger.info('[%s] Data Received on port: [22] from [%s:%d] - [%s %s] ' % (current_time, self.addr0, self.addr1, username, password,))
        return paramiko.AUTH_FAILED

def start_ssh_server():
    global ssh_port
    ssh_key = generate_or_read_ssh_key()

    server_socket = socket()
    server_socket.bind((BIND_IP, ssh_port))
    server_socket.listen(5)

    while True:
        client, addr = server_socket.accept()
        current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S%f")[:-3]
        logger.info('[%s] Connection Received on port: [22] from: [%s:%d]' % (current_time, addr[0], addr[1]))
        
        try:
            transport = paramiko.Transport(client)
            transport.add_server_key(ssh_key)
            server = SSHServer(addr[0], addr[1])
            transport.start_server(server=server)
        except Exception as e:
            pass

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

config = configparser.ConfigParser()
config.read(config_filepath)

ports = config.get('default', 'ports', raw=True, fallback="22,80,443,8080,8888,9999")
logfile = config.get('default', 'logfile', raw=True, fallback="honeypwned.log")
logger = setup_logging()


print("[*] Ports: %s" % ports)
print("[*] Logfile: %s" % logfile)

ports_list = []
listeners_thread = {}

# Open analyzer.py using subprocess
subprocess.Popen(["python3", "analyzer.py"])

# Try splitting the ports
try:
    ports_list = ports.split(',')
except Exception as e:
    print('[!] Error getting ports: %s', ports)
    sys.exit(1)

# Check if there are any ports provided in ini file
if len(ports) < 1:
    print('[!] No ports provided.')
    sys.exit(1)

# Start SSH server if SSH port is configured
if '22' in ports_list:
    ports_list.remove('22')
    ssh_thread = threading.Thread(target=start_ssh_server)
    ssh_thread.start()

# Check if port 80 is in the ports list
if '80' in ports_list:
    ports_list.remove('80')
    flask_thread = threading.Thread(target=start_flask_server, args=(logger,))
    flask_thread.start()

# Start listener threads for other ports
for port in ports_list:
    listeners_thread[port] = threading.Thread(target=start_new_listener_thread, args=(port,))
    listeners_thread[port].start()

