from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt

import logging
from logging.handlers import RotatingFileHandler
from urllib.parse import unquote
import base64
import os
import sys
import shutil
import pyotp
import time
import re
import shlex
import subprocess
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///backend.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

DEBUG_MODE = os.getenv("FLASK_DEBUG")
KEYS_DIR = "/keys"
LOGS_DIR = "/logs"
app.secret_key = 'welp_this_shouldnt_be_exposed'

db = SQLAlchemy(app)

os.makedirs(f"{KEYS_DIR}", exist_ok=True)
os.makedirs(f"{LOGS_DIR}", exist_ok=True)

# Create a logger
def configure_logging(logs_dir):
    # Full path for the log file
    log_filename = f'{logs_dir}/app.log'
    
    # Create a rotating file handler
    file_handler = RotatingFileHandler(
        filename=log_filename,
        mode='a',  # append mode
        maxBytes=10*1024,  # 10 KB max file size
        backupCount=3,  # Keep 5 backup files
        encoding='utf-8'
    )
    
    # Configure logging format
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    # Configure logging levels
    file_handler.setLevel(logging.WARNING)
    
    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.WARNING)
    
    # Add the file handler to the root logger
    logger.addHandler(file_handler)
    
    # Suppress Flask and Werkzeug INFO logs
    logging.getLogger('flask').setLevel(logging.ERROR)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    
    return logger

flask_logger = configure_logging(LOGS_DIR)

# Define the User model
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_user = db.Column(db.String(50), unique=True, nullable=False)
    api_pass = db.Column(db.String(100), nullable=False)  # Adjust length for hashed passwords
    email = db.Column(db.String(120), unique=True, nullable=False)
    admin_flag = db.Column(db.Boolean, default=False, nullable=False)
    totp_seed = db.Column(db.String(32), nullable=False) 

class Servers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    svr_name = db.Column(db.String(50), unique=True, nullable=False)
    svr_user = db.Column(db.String(50), nullable=False)
    svr_ip = db.Column(db.String(20), nullable=False)   
    netstat_cmd = db.Column(db.String(50), nullable=False)
    webroot = db.Column(db.String(50), nullable=False)


def create_tables():
    with app.app_context():
        # Users.__table__.drop(db.engine)
        # Servers.__table__.drop(db.engine)
        db.create_all()

### VALIDATION FUNCTIONS

def is_valid_ipv4(ip):
    # Regular expression pattern for validating an IPv4 address
    pattern = r'^((25[0-5]|(2[0-4][0-9])|([01]?[0-9][0-9]?))\.){3}(25[0-5]|(2[0-4][0-9])|([01]?[0-9][0-9]?))$'
    
    # Use fullmatch to check if the input string matches the pattern
    return re.fullmatch(pattern, ip) is not None

def is_valid_netstat(netstat_cmd):
    if netstat_cmd == "freebsd":
        return "netstat -anf inet"
    if netstat_cmd == "debian":
        return "ss -antup"
    return None

### HELPER FUNCTIONS

def generate_base32_secret(length=32):
    random_bytes = os.urandom(length)
    base32_secret = base64.b32encode(random_bytes).decode('utf-8')
    return base32_secret

def send_otp_via_email(to_email, otp):
    # Set up email configuration (replace with your settings)
    from_email = 'noreply@tree-haus.org'
    email_password = 'welp_this_shouldnt_be_exposed'

    msg = MIMEText(f'Your OTP is: {otp}. The OTP expires in 5 minutes. Keep it safe, do not reveal this to anyone else, yadda yadda.')
    msg['Subject'] = 'Your OTP Code'
    msg['From'] = from_email
    msg['To'] = to_email

    result = ""    
    if to_email == "superadmin":
        result += f"An OTP has been sent to {to_email}"
        print(f"[!] superadmin: {otp}", file=sys.stderr)
    else:
        try:
            # Create an SMTP connection
            with smtplib.SMTP('smtp.tree-haus.org', 587) as server:
                server.starttls()
                server.login(from_email, email_password)
                server.send_message(msg)
            result += f"An OTP has been sent to {to_email}"
        except Exception as e:
            result += f"Failed to send email to {to_email}: {e}"
            if DEBUG_MODE:
                result += f"\n------------------\n{msg}"

    return result

def generate_pyotp(secret, interval=300):
    totp = pyotp.TOTP(secret)
    return totp.now()

def get_authed_user():
    if 'user_id' not in session or not session.get('otp'):
        return None
    
    user = db.get_or_404(Users, session['user_id'])

    if not user:
        return None

    return user

### SUPERADMIN FUNCTIONS

@app.route('/dmzapp/api/v1/superadmin/shell', methods=['GET'])
def changepass():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401

    if user.api_user != "superadmin":
        return jsonify({"message": "Unauthorized"}), 403

    random_bytes = os.urandom(16)
    # Convert to a Base64 string and strip to desired length
    password = base64.urlsafe_b64encode(random_bytes).decode('utf-8')[:16]
    keyloc = os.getenv('SHELLINABOX_KEY')

    try:
        cmd_str = f"ssh -oStrictHostKeyChecking=false -i {keyloc} root@shell  \"echo 'superadmin:{password}' | chpasswd\""
        command = shlex.split(cmd_str)
        output = subprocess.check_output(command, universal_newlines=True)
        html = '<a id="admin_link" href="/dmzapp/superadmin/shell/" target="_blank">here</a>'
        return jsonify({"result": f"Log in {html} as superadmin, with password {password}"}), 200

    except subprocess.CalledProcessError as e:        
        return jsonify({"error": "Failed to change pass", "details": str(e)}), 500

### API LOGGING FUNCTIONS

@app.route('/dmzapp/api/v1/viewlog/<logfile>', methods=['GET'])
def view_log(logfile=""):
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401

    if not user.admin_flag:
        return jsonify({"message": "Unauthorized"}), 403

    if logfile == "":
        return jsonify({"error": "No logfile specified"}), 400

    # get the logfile
    logfile = unquote(logfile)
    file_path = os.path.join(LOGS_DIR, logfile)
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            lines = file.readlines()  # Read all lines from the file
        # Clean lines by stripping newline characters
        lines = [line.strip() for line in lines]
        show_lines = []
        for i in range(max(0,len(lines) - 20), len(lines)):
            show_lines.append(lines[i])
        return jsonify({"logs": show_lines}), 200  # Return contents as JSON with a 200 OK status
    except FileNotFoundError:
        return jsonify({"error": f"Logfile not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

### API SERVER FUNCTIONS

@app.route('/dmzapp/api/v1/servers', methods=['GET'])
def view_servers():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401

    # Retrieve all servers from the database
    all_svrs = db.session.execute(db.select(Servers).order_by(Servers.svr_name)).scalars()

    # Prepare the response with user details
    svr_list = [
        {
            "svr_name": svr.svr_name,
            "svr_user": svr.svr_user,
            "svr_ip": svr.svr_ip,            
            "netstat_cmd": svr.netstat_cmd,
            "webroot": svr.webroot
        }
        for svr in all_svrs
    ]

    return jsonify({"servers": svr_list}), 200


@app.route('/dmzapp/api/v1/servers/<svr_name>/<protocol>:<int:portno>', methods=['GET'])
@app.route('/dmzapp/api/v1/servers/<svr_name>/<protocol>', methods=['GET'])
@app.route('/dmzapp/api/v1/servers/<svr_name>', methods=['GET'])
def get_server_netstat(svr_name, protocol="", portno=""):
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401

    server = Servers.query.filter_by(svr_name=svr_name).first()
    
    if not server:
        return jsonify({"error": "Server not found"}), 404

    # Run the netstat command
    flask_logger.warning(f'Svr netstat ran: {user.api_user}: {server.svr_name}')
    try:
        cmd_str = f"ssh -oStrictHostKeyChecking=false -i {KEYS_DIR}/{server.svr_name} {server.svr_user}@{server.svr_ip} {server.netstat_cmd}"
        command = shlex.split(cmd_str)
        output = subprocess.check_output(command, universal_newlines=True)
        
        lines = output.splitlines()
        filtered_lines = []
        for line in lines:
            if protocol in line and f".{portno}" in line:
                filtered_lines.append(line)        
        return jsonify({"result": filtered_lines}), 200

    except subprocess.CalledProcessError as e:
        logging.error(f'Svr error: {user.api_user}: {server.svr_name}')
        return jsonify({"error": "Failed to run command", "details": str(e)}), 500


### API SERVER MANAGEMENT FUNCTIONS

@app.route('/dmzapp/api/v1/servers/manage/delete', methods=['POST'])
def manage_delete_server():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401

    if not user.admin_flag:
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json()
    # Validate input
    if 'svr_name' not in data:
        return jsonify({"message": "Missing svr_name"}), 400

    if data['svr_name'] == "pfsense":
        return jsonify({"message": "Cannot delete pfsense"}), 400

    # Find the server to delete
    svr_to_delete = Servers.query.filter_by(svr_name=data['svr_name']).first()
    
    if not svr_to_delete:
        return jsonify({"message": "Server not found"}), 404

    # remove the key file and Delete the server from the database
    try:
        keyfile = f"{KEYS_DIR}/{svr_name}"
        os.remove(keyfile)
    except Exception as e:
        pass

    db.session.delete(svr_to_delete)
    db.session.commit()

    return jsonify({"message": "Server deleted successfully"}), 200

@app.route('/dmzapp/api/v1/servers/manage/edit', methods=['POST'])
def manage_edit_server():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401

    if not user.admin_flag:
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json()
    # Validate input
    if 'svr_name' not in data:
        return jsonify({"message": "Missing svr_name"}), 400

    if data['svr_name'] == "pfsense":
        return jsonify({"message": "Cannot edit pfsense"}), 400

    # Find the user to edit
    svr_to_edit = Servers.query.filter_by(svr_name=data['svr_name']).first()
    
    if not svr_to_edit:
        return jsonify({"message": "Server not found"}), 404

    # Update fields if provided
    if 'svr_user' in data:
        if data['svr_user'].isalnum():
            svr_to_edit.svr_user = data['svr_user']
        else:
            return jsonify({"message": "Invalid user name"}), 400
    if 'svr_ip' in data:      
        if not is_valid_ipv4(data['svr_ip']):
            return jsonify({"message": "Invalid ipv4 address"}), 400
        svr_to_edit.svr_ip = data['svr_ip']
    if 'netstat_cmd' in data:
        actual_cmd = is_valid_netstat(data['netstat_cmd'])
        if actual_cmd == None:
            return jsonify({"message": "Invalid netstat (either 'freebsd' or 'debian')"}), 400
        svr_to_edit.netstat_cmd = actual_cmd
    if 'webroot' in data:
        svr_to_edit.webroot = data['webroot']        

    if 'svr_key' in data:
        # decode the svr_key and drop it to a file under /keys/[svr_name]
        try:
            keydata = base64.b64decode(data['svr_key'])
            keyfile = f"{KEYS_DIR}/{svr_to_edit.svr_name}"
            with open(keyfile, 'wb') as file:
                file.write(keydata.replace(b"\x0d\x0a", b"\x0a"))
            os.chmod(keyfile,0o600)
        except Exception as e:
            return jsonify({"message": f"Unable to update the key file: {e}"}), 500

    # Commit changes to the database
    db.session.commit()

    return jsonify({"message": "Server updated successfully"}), 200

@app.route('/dmzapp/api/v1/servers/manage/new', methods=['POST'])
def manage_new_server():
    '''
    curl -b ~/cookies.txt -c ~/cookies.txt http://localhost:5000/dmzapp/api/v1/servers/manage/new --json "{\"svr_name\": \"hauspf\", \"svr_user\": \"root\", \"svr_ip\": \"192.168.41.1\", \"netstat_cmd\": \"freebsd\", \"webroot\": \"https://192.168.41.1\", \"svr_key\": \"$(base64 -w0 pfhaus.key)\"}"
    '''

    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401
    
    if not user.admin_flag:
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json()
    # Validate input
    required_fields = ['svr_name', 'svr_user', 'svr_ip', 'netstat_cmd', 'webroot', 'svr_key']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    # Check if the server already exists
    existing_svr = Servers.query.filter((Servers.svr_name == data['svr_name'])).first()
    if existing_svr:
        return jsonify({"message": "Server already exists"}), 409

    # validate
    if not data['svr_user'].isalnum():
        return jsonify({"message": "Invalid user name"}), 400
    if not is_valid_ipv4(data['svr_ip']):
        return jsonify({"message": "Invalid ipv4 address"}), 400

    actual_cmd = is_valid_netstat(data['netstat_cmd'])
    if actual_cmd == None:
        return jsonify({"message": "Invalid netstat (either 'freebsd' or 'debian')"}), 400

    # decode the svr_key and drop it to a file under /keys/[svr_name]
    try:
        keydata = base64.b64decode(data['svr_key'])
        keyfile = f"{KEYS_DIR}/{data['svr_name']}"
        with open(keyfile, 'wb') as file:
            file.write(keydata.replace(b"\x0d\x0a", b"\x0a"))
        os.chmod(keyfile,0o600)
    except Exception as e:
        return jsonify({"message": f"Unable to create the key file: {e}"}), 500

    # Create a new server instance
    new_svr = Servers(
        svr_name=data['svr_name'],
        svr_user=data['svr_user'],
        svr_ip=data['svr_ip'],
        netstat_cmd=actual_cmd,
        webroot=data['webroot']
    )

    # Add the server to the database
    db.session.add(new_svr)
    db.session.commit()

    return jsonify({"message": "Server entry created successfully"}), 201

### API USER MANAGEMENT FUNCTIONS

@app.route('/dmzapp/api/v1/users/manage/delete', methods=['POST'])
def manage_delete_user():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401

    if not user.admin_flag:
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json()
    # Validate input
    if 'api_user' not in data:
        return jsonify({"message": "Missing api_user"}), 400

    # Find the user to delete
    user_to_delete = Users.query.filter_by(api_user=data['api_user']).first()    
    
    if not user_to_delete:
        return jsonify({"message": "User not found"}), 404

    # block deletion of superadmin
    if user_to_delete.api_user == "superadmin":
        return jsonify({"message": "Cannot delete superadmin"}), 403

    # Delete the user from the database
    db.session.delete(user_to_delete)
    db.session.commit()

    return jsonify({"message": "User deleted successfully"}), 200



@app.route('/dmzapp/api/v1/users/manage/edit', methods=['POST'])
def manage_edit_user():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401

    if not user.admin_flag:
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json()
    # Validate input
    if 'api_user' not in data:
        return jsonify({"message": "Missing api_user"}), 400

    # Find the user to edit
    user_to_edit = Users.query.filter_by(api_user=data['api_user']).first()
    
    if not user_to_edit:
        return jsonify({"message": "User not found"}), 404

    # block editing of superadmin
    if user_to_edit.api_user == "superadmin":
        return jsonify({"message": "Cannot edit superadmin"}), 403


    # Update fields if provided
    if 'api_pass' in data:
        user_to_edit.api_pass = bcrypt.hashpw(data['api_pass'].encode("utf-8"), bcrypt.gensalt()) # Hash password
    if 'email' in data:
        user_to_edit.email = data['email']
    if 'admin_flag' in data:
        user_to_edit.admin_flag = int(data['admin_flag'].lower()=='true')

    # Commit changes to the database
    db.session.commit()

    return jsonify({"message": "User updated successfully"}), 200



@app.route('/dmzapp/api/v1/users/manage/new', methods=['POST'])
def manage_new_user():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401
    
    if not user.admin_flag:
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json()
    # Validate input
    required_fields = ['api_user', 'api_pass', 'email', 'admin_flag']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    # Check if the user already exists
    existing_user = Users.query.filter((Users.api_user == data['api_user']) | 
                                       (Users.email == data['email'])).first()
    if existing_user:
        return jsonify({"message": "User already exists"}), 409

    # Create a new user instance
    new_user = Users(
        api_user=data['api_user'],
        api_pass=bcrypt.hashpw(data['api_pass'].encode("utf-8"), bcrypt.gensalt()),
        email=data['email'],
        admin_flag=int(data['admin_flag'].lower()=='true'),
        totp_seed=generate_base32_secret()
    )

    # Add the user to the database
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201


@app.route('/dmzapp/api/v1/users/manage', methods=['GET'])
def manage_users():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401
    
    if not user.admin_flag:
        return jsonify({"message": "Unauthorized"}), 403

    # Retrieve all users from the database
    all_users = db.session.execute(db.select(Users).order_by(Users.api_user)).scalars()

    # Prepare the response with user details
    users_list = [
        {
            "api_user": u.api_user,
            "email": u.email,
            "admin_flag": u.admin_flag
        }
        for u in all_users
    ]

    return jsonify({"users": users_list}), 200


### API USER FUNCTIONS

@app.route('/dmzapp/api/v1/users/register', methods=['POST'])
def register_user():
    data = request.get_json()

    # Validate input
    required_fields = ['api_user', 'api_pass', 'email']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    # Check if the user already exists
    existing_user = Users.query.filter((Users.api_user == data['api_user']) | 
                                       (Users.email == data['email'])).first()
    if existing_user:
        return jsonify({"message": "User already exists"}), 409

    # Create a new user instance
    new_user = Users(
        api_user=data['api_user'],
        api_pass=bcrypt.hashpw(data['api_pass'].encode("utf-8"), bcrypt.gensalt()),
        email=data['email'],
        admin_flag=False,
        totp_seed=generate_base32_secret()
    )

    # Add the user to the database
    db.session.add(new_user)
    db.session.commit()
    flask_logger.warning(f'New Registration: {new_user.api_user}')
    return jsonify({"message": "User registered successfully. Check your email for further instructions."}), 201

@app.route('/dmzapp/api/v1/users/profile', methods=['GET'])
def get_user_profile():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401
    
    # Return user profile
    return jsonify({
        "api_user": user.api_user,
        "email": user.email,
        "admin_flag": user.admin_flag
    }), 200

@app.route('/dmzapp/api/v1/users/profile/edit', methods=['POST'])
def edit_user_profile():
    # Check if the user is authenticated
    user = get_authed_user()
    if user == None:
        return jsonify({"message": "Unauthorized"}), 401
    
    data = request.get_json()

    # Validate input
    if 'api_pass' not in data and 'email' not in data:
        return jsonify({"message": "Missing fields to update"}), 400

    # Update fields if provided
    try:
        if 'api_pass' in data:
            user.api_pass = bcrypt.hashpw(data['api_pass'].encode("utf-8"), bcrypt.gensalt())

        if 'email' in data:
            user.email = data['email']

        if 'admin_flag' in data:
            user.admin_flag = int(data['admin_flag'].lower()=='true')
    except:
        return jsonify({"message": "Invalid data"}), 400

    # Commit changes to the database
    db.session.commit()
    flask_logger.warning(f'Edited Profile: {user.api_user}')
    return jsonify({"message": "Profile updated successfully"}), 200


### API LOGIN FUNCTIONS

@app.route('/dmzapp/api/v1/login', methods=['POST'])
def login_user():
    data = request.get_json()

    # Validate input
    required_fields = ['api_user', 'api_pass']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    user = Users.query.filter_by(api_user=data['api_user']).first()

    if user and bcrypt.checkpw(data['api_pass'].encode("utf-8"), user.api_pass):
        session['user_id'] = user.id
        session['otp'] = False
        return jsonify({"message": "Login successful, verify OTP", "api_user": user.api_user}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/dmzapp/api/v1/login/otp', methods=['GET'])
def request_otp():
    # Check if the user is authenticated
    if 'user_id' not in session:
        return jsonify({"message": "Unauthorized"}), 401

    user = db.get_or_404(Users, session['user_id'])
    
    if not user:
        return jsonify({"message": "Invalid session"}), 401

    # Generate the otp for the username

    otp = generate_pyotp(user.totp_seed)
    result = send_otp_via_email(user.email, otp)

    return jsonify({"message": result}), 200

@app.route('/dmzapp/api/v1/login/otp', methods=['POST'])
def verify_otp():
    # Check if the user is authenticated
    if 'user_id' not in session:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()

    # Validate input
    if 'otp' not in data:
        return jsonify({"message": "Missing OTP"}), 400

    user = db.get_or_404(Users, session['user_id'])
    
    if not user:
        return jsonify({"message": "Invalid session"}), 401

    # Verify the OTP
    try:
        if data['otp'] == generate_pyotp(user.totp_seed):
            session['otp'] = True
            flask_logger.warning(f'Successful Login: {user.api_user}')
            return jsonify({"message": "OTP verified successfully"}), 200
    except Exception as e:
        pass
    return jsonify({"message": "Invalid OTP"}), 401

@app.route('/dmzapp/api/v1/logout', methods=['GET'])
def logout():
    user = get_authed_user()
    if user == None:
        return
    session.clear()
    flask_logger.warning(f'Logged out: {user.api_user}')
    return jsonify({"message": "logged out"}), 200

### END API FUNCTIONS

# @app.route('/')
# def hello():
#     if DEBUG_MODE:
#         return "Debug is enabled\n"
#     return ""

if __name__ == "__main__":
    create_tables()
    app.run(host='0.0.0.0', port=5000)
