from flask import Flask, render_template, redirect, url_for

import os
import logging
from logging.handlers import RotatingFileHandler

LOGS_DIR = "/logs"

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
        fmt='%(asctime)s - %(levelname)s - %(message)s',
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
    logging.getLogger('flask').setLevel(logging.INFO)
    logging.getLogger('werkzeug').setLevel(logging.INFO)
    
    return logger

flask_logger = configure_logging(LOGS_DIR)
app = Flask(__name__)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/dmzapp/')
def dmzapp():
    return redirect(url_for('login'))

@app.route('/dmzapp/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/dmzapp/logout', methods=['GET'])
def logout():
    return render_template('logout.html')

@app.route('/dmzapp/register', methods=['GET'])
def register():
    return render_template('register.html')

@app.route('/dmzapp/manage', methods=['GET'])
def manage():
    return render_template('manage.html')

@app.route('/dmzapp/dashboard', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/dmzapp/editprofile', methods=['GET'])
def editprofile():
    return render_template('editprofile.html')

@app.route('/dmzapp/otp', methods=['GET'])
def otp():
    return render_template('otp.html')

if __name__ == '__main__':    
    app.run(host='0.0.0.0', port=5000)
