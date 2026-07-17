import email_notifications
from flask import Flask, Response, request, render_template, redirect, session, make_response, jsonify
from flask_jwt_extended import set_access_cookies, create_access_token, jwt_required, JWTManager, get_jwt_identity
from secret_ket import jwt_secret_key, flask_secret_key
from datetime import timedelta
import time, json, os, traceback
from bcrypt import *
from hmac import compare_digest
import boto3
from werkzeug.utils import secure_filename
from flask_cors import CORS
from functools import wraps

import os
import json
import hashlib
import secrets
import string
import random
import time
from datetime import datetime
from dotenv import load_dotenv
# ---------------- METRICS STORE ----------------
metrics = {
    "total_logins": 0,
    "successful_uploads": 0,
    "download_attempts": 0,
    "failed_secret_reconstructions": 0,
    "anomalies_detected": 0
}

blocked_users = {}
# Load environment variables from .env file
load_dotenv()

from secret_sharing import generate_shares
from reconstruct_secret import reconstruct_secret
from utils import display_shares
from email_notifications import notify_share_generated, notify_secret_reconstructed

# CRYPT-DAC IMPORTS
from crypto_utils import (
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    rsa_wrap_key,
    rsa_unwrap_key,
    generate_rsa_keypair
)
from utils_wrapped_keys import save_wrapped_key, load_wrapped_key

# ---------------- APP INIT ----------------
app = Flask(__name__)
CORS(app)
app.secret_key = flask_secret_key
app.config['JWT_SECRET_KEY'] = jwt_secret_key
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
jwt = JWTManager(app)
# ---------------- SECURITY METRICS ----------------
metrics = {
    "total_uploads": 0,
    "total_downloads": 0,
    "failed_download_attempts": {},
    "anomalies_detected": 0
}
# ---------------- AWS CONFIG (UNCHANGED) ----------------
S3_BUCKET_NAME = "my-flask-upload-buckets-25-26"
AWS_ACCESS_KEY = "AKIA2NNTTSYMPZ4MBT4E"
AWS_SECRET_KEY = "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"
AWS_REGION = "eu-north-1"

s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)

sender_email = os.getenv('EMAIL_SENDER')
sender_password = os.getenv('EMAIL_PASSWORD')

# ---------------- RSA KEY STORE ----------------
RSA_KEY_DIR = "rsa_keys"
os.makedirs(RSA_KEY_DIR, exist_ok=True)

def get_user_rsa_keys(email):
    priv_path = f"{RSA_KEY_DIR}/{email}_private.pem"
    pub_path = f"{RSA_KEY_DIR}/{email}_public.pem"

    if not os.path.exists(priv_path):
        priv, pub = generate_rsa_keypair()
        open(priv_path, "wb").write(priv)
        open(pub_path, "wb").write(pub)

    return open(priv_path, "rb").read(), open(pub_path, "rb").read()

# ---------------- SECURITY MIDDLEWARE ----------------
# Fixed: Added explicit error=None to prevent premature error messages
@app.before_request
def security_check():
    # Skip authentication for login, register, static files, and main route
    if request.endpoint in ['login_page', 'register_page', 'static', 'main']:
        return
    
    # Only check authentication for specific protected routes
    protected_routes = ['upload_file', 'list_files', 'download_file', 'protected', 'logout_logic']
    if request.endpoint in protected_routes:
        if 'is_logged_in' not in session or not session.get('is_logged_in'):
            print(f"DEBUG: Security check failed for {request.endpoint} - redirecting to login")
            return redirect("/login")

# ---------------- HELPERS ----------------
def is_office_hours():
    current_hour = datetime.now().hour
    return 9 <= current_hour < 18

def load_user_credentials():
    with open('user_database/user_credentials.json', 'r') as f:
        return json.load(f)

def role_required(*allowed_roles):
    """
    Decorator to restrict access to users with specific roles.
    Usage: @role_required('ADMIN', 'MANAGER')
    """
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            # Get user role from session first
            user_role = session.get('user_role')
            
            # If not in session, get from database
            if not user_role:
                user_email = get_jwt_identity()
                users = load_user_credentials()
                for u in users['cred']:
                    if u['email'] == user_email:
                        user_role = u['role']
                        break
            
            # Check if user has required role
            if user_role not in allowed_roles:
                return "Access denied: Insufficient privileges", 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---------------- AUTH ROUTES (UNCHANGED) ----------------
@app.route('/', methods=['POST', 'GET'])
def main():
    # Clear any existing sessions for security
    if request.method == 'POST':
        session.clear()
    
    if 'is_logged_in' not in session or not session.get('is_logged_in'):
        if request.method == 'POST':
            name = request.form['user_name']
            password = request.form['paswd']

            print(f"DEBUG: Login attempt - Username: {name}")

            with open("user_database/user_credentials.json") as file:
                user_cred = json.load(file)

            user = next((u for u in user_cred['cred'] if compare_digest(name, u['user_id'])), None)
            
            if not user:
                print(f"DEBUG: User not found - {name}")
                return render_template("login.html", error="Invalid username or password")

            print(f"DEBUG: User found - {user['user_id']}, role: {user['role']}")
            email = user['email']
            if email in blocked_users:
                if datetime.now() < blocked_users[email]:
                    return render_template(
                        "login.html",
                        error="Account temporarily blocked. Try again after some time."
                    )
                else:
                    # unblock after time expires
                    del blocked_users[email]

            if checkpw(password.encode(), user['password'].encode()):
                print(f"DEBUG: Password correct for {user['user_id']}")
                
                if user['status'] != 'ACTIVE':
                    print(f"DEBUG: Account not active for {user['user_id']}")
                    return render_template("login.html", error="Account is not active")

                session['user_id'] = user['user_id']
                session['user_role'] = user['role']
                session['is_logged_in'] = True

                # Debug logging
                print(f"DEBUG: User {user['user_id']} logged in with role {user['role']}")

                token = create_access_token(identity=user['email'])
                resp = make_response(render_template("index.html", name=user['user_id'], role=user['role']))
                set_access_cookies(resp, token)
                return resp
            else:
                print(f"DEBUG: Password incorrect for {user['user_id']}")
                return render_template("login.html", error="Invalid username or password")
        return render_template("login.html", error=None)
    
    # Debug logging for session
    print(f"DEBUG - Session data: user_id={session.get('user_id')}, user_role={session.get('user_role')}, is_logged_in={session.get('is_logged_in')}")
    
    return render_template("index.html", name=session['user_id'], role=session['user_role'])

@app.route('/login')
def login_page():
    # Clear any session data that might contain error messages
    session.clear()
    print("DEBUG: Login page accessed, session cleared and error set to None")
    return render_template("login.html", error=None)

@app.route("/logout")
def logout_logic():
    session.clear()
    resp = make_response(redirect("/login"))
    resp.delete_cookie("access_token")
    # Clear all cookies
    for cookie in request.cookies:
        resp.delete_cookie(cookie)
    print("DEBUG: User logged out, session and cookies cleared")
    return resp

@app.route("/register", methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        role = request.form['role']
        password = request.form['passwd']
        password_confirm = request.form['passwd_re']
        
        if password != password_confirm:
            return render_template("register.html", error="Passwords do not match")
        
        try:
            with open('user_database/user_credentials.json', 'r+') as f:
                user_data = json.load(f)
                
                # Check if user already exists
                for user in user_data['cred']:
                    if user['email'] == email:
                        return render_template("register.html", error="Email already registered")
                
                # Add new user
                hashed_password = hashpw(password.encode(), gensalt()).decode()
                new_user = {
                    'user_id': f"{first_name}_{last_name}",
                    'email': email,
                    'password': hashed_password,
                    'role': role,
                    'status': 'ACTIVE'
                }
                user_data['cred'].append(new_user)
                
                f.seek(0)
                json.dump(user_data, f, indent=2)
                f.truncate()
            
            return redirect("/login")
        except Exception as e:
            return render_template("register.html", error=f"Registration failed: {str(e)}")
    
    return render_template("register.html")

@app.route('/list-files', methods=['GET'])
@jwt_required()
def list_files():
    try:
        # List files in S3 bucket
        response = s3.list_objects_v2(Bucket=S3_BUCKET_NAME)
        files = [obj['Key'] for obj in response.get('Contents', [])]
        
        # Get file upload times and sort by most recent first
        file_times = {}
        try:
            for obj in response.get('Contents', []):
                file_times[obj['Key']] = obj.get('LastModified')
        except:
            # If LastModified not available, use current time
            from datetime import datetime
            current_time = datetime.now()
            for obj in response.get('Contents', []):
                file_times[obj['Key']] = current_time
        
        # Sort files by time (most recent first)
        files_sorted = sorted(files, key=lambda x: file_times.get(x, ''), reverse=True)
        
        # Get threshold information for each file
        file_thresholds = {}
        with open("secrets.txt", "r") as f:
            for line in f:
                if "Filename:" in line:
                    parts = line.strip().split(", ")
                    filename = parts[0].split(": ")[1]
                    
                    # Check if Threshold field exists
                    threshold = 3  # default threshold
                    for part in parts:
                        if part.startswith("Threshold:"):
                            threshold = int(part.split(": ")[1])
                            break
                    
                    file_thresholds[filename] = threshold
        
        return render_template("file_list.html", files=files_sorted, file_thresholds=file_thresholds)
    except Exception as e:
        return f"Error listing files: {str(e)}", 500

@app.route('/protected', methods=['POST'])
@jwt_required()
def protected():
    role = request.form.get('role')
    user_role = session.get('user_role')
    
    if role == 'project details':
        protected_msg = "This is a secure project details page. Access granted."
        return render_template("details.html", name=session['user_id'], role=user_role, infotype=role, protected_msg=protected_msg)
    elif role == 'firm details':
        protected_msg = "This is a secure company details page. Access granted."
        return render_template("details.html", name=session['user_id'], role=user_role, infotype=role, protected_msg=protected_msg)
    elif role == 'employee_details' and user_role == 'ADMIN':
        users = load_user_credentials()
        return render_template("details.html", name=session['user_id'], role=user_role, infotype=role, protected_msg=users['cred'])
    else:
        return "Access denied", 403

# ---------------- UPLOAD (AES + RSA + SSS) ----------------
@app.route('/upload', methods=['GET', 'POST'])
@role_required('ADMIN', 'MANAGER')
def upload_file():
        # -------- CONTEXT-AWARE ACCESS (TIME BASED) --------
    user_role = session.get('user_role')
    current_hour = datetime.now().hour

    if user_role == "MANAGER":
        if current_hour < 9 or current_hour >= 18:
            return "Upload allowed only between 9 AM and 6 PM for MANAGER role", 403

    user_role = session.get('user_role')

    # ---- CONTEXT-AWARE ACCESS RULE (TIME-BASED) ----
    if user_role == 'MANAGER' and not is_office_hours():
        metrics["anomalies_detected"] += 1

        with open("anomaly_log.txt", "a") as f:
            f.write(f"{datetime.now()} - Manager upload blocked (outside office hours)\n")

        return "Access denied: Managers can upload files only between 9AM and 6PM", 403

    try:
        if request.method == 'GET':
            return render_template("upload_page.html")
        
        if 'file' not in request.files:
            return "No file", 400

        file = request.files['file']
        filename = secure_filename(file.filename)
        print(f"DEBUG: Processing upload for file: {filename}")

        # AES ENCRYPT
        plaintext = file.read()
        aes_key = generate_aes_key()
        encrypted_data = aes_encrypt(plaintext, aes_key)
        print(f"DEBUG: File encrypted successfully")

        # Upload encrypted file
        s3.put_object(Bucket=S3_BUCKET_NAME, Key=filename, Body=encrypted_data)
        print(f"DEBUG: File uploaded to S3: {filename}")

        # Wrap AES key per EMPLOYEE
        users = load_user_credentials()
        for u in users['cred']:
            if u['role'] == 'EMPLOYEE':
                _, pub = get_user_rsa_keys(u['email'])
                wrapped = rsa_wrap_key(aes_key, pub)
                save_wrapped_key(filename, u['email'], wrapped)
        print(f"DEBUG: AES keys wrapped for {len([u for u in users['cred'] if u['role'] == 'EMPLOYEE'])} employees")

        # SSS
        secret = request.form['secret']
        threshold = int(request.form['threshold'])
        secret_numeric = sum(ord(c) for c in secret)
        print(f"DEBUG: Secret '{secret}' converted to numeric: {secret_numeric}")

        with open("secrets.txt", "a") as f:
            f.write(f"Filename: {filename}, Secret: {secret_numeric}, OriginalSecret: {secret}, Threshold: {threshold}\n")

        recipients = [u['email'] for u in users['cred'] if u['role'] == 'EMPLOYEE']
        shares = generate_shares(secret_numeric, len(recipients), threshold)
        print(f"DEBUG: Generated shares from secret {secret_numeric}: {shares}")

        # Create mapping of share to recipient for tracking
        share_mapping = {}
        for i, email in enumerate(recipients):
            share_value = str(shares[i][1])  # Exact share value (no padding)
            share_mapping[email] = share_value
            try:
                notify_share_generated(email, sender_email, sender_password, str(shares[i]))
                print(f"DEBUG: Sent share {shares[i]} to {email} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (Share: {share_value})")
            except Exception as e:
                print(f"WARNING: Failed to send email to {email}: {str(e)}")
                print(f"DEBUG: Share {shares[i]} for {email} (Share: {share_value}) - EMAIL NOT SENT")
        
        # Show all sent shares for user reference
        print(f"DEBUG: ALL SHARES SENT (Any {threshold} of these will work):")
        for i, email in enumerate(recipients):
            share_value = str(shares[i][1])
            print(f"DEBUG:   Share {i+1}: {share_value} (sent to {email})")
        
        # Save share mapping to file for verification
        with open("share_tracking.txt", "a") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - File: {filename} - Share mapping: {share_mapping}\n")
        metrics["total_uploads"] += 1
        print(f"DEBUG: Upload completed successfully, returning JSON response")
        return jsonify({
            "message": "File uploaded successfully! Shares have been generated and sent to employees via email. Employees must collect their shared keys (sent via email) to gain access to download the file.",
            "redirect": "/list-files"
        }), 200
        
    except Exception as e:
        print(f"DEBUG: Upload error: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({
            "message": f"Upload failed: {str(e)}",
            "redirect": None
        }), 500

# ---------------- DOWNLOAD (SSS → RSA → AES) ----------------
@app.route('/download/<filename>', methods=['POST'])
@jwt_required()
def download_file(filename):
    email = get_jwt_identity()
    metrics["total_downloads"] += 1
    # Get threshold for this file
    threshold = 3  # default
    try:
        with open("secrets.txt", "r") as f:
            for line in f:
                if filename in line:
                    # Parse threshold more safely
                    parts = line.strip().split(", ")
                    for part in parts:
                        if part.startswith("Threshold:"):
                            threshold = int(part.split(": ")[1])
                            print(f"DEBUG: Found threshold {threshold} for file {filename}")
                            break
                    break
    except Exception as e:
        print(f"DEBUG: Error reading threshold: {e}")
        threshold = 3  # fallback
    
    print(f"DEBUG: Using threshold: {threshold}")

    # Collect all share values from the form (any order, any positions)
    shares = []
    print(f"DEBUG: Looking for shares with threshold {threshold}")
    
    # Get ALL form data that looks like share values
    for key, value in request.form.items():
        if key.startswith('s') and value.isdigit():
            share_value = int(value)
            shares.append((len(shares) + 1, share_value))  # Use sequential index
            print(f"DEBUG: Found share {key}: {share_value}")
    
    print(f"DEBUG: Total shares collected: {shares}")
    print(f"DEBUG: Form data received: {dict(request.form)}")

    if len(shares) < threshold:
        return f"Insufficient shares. Need at least {threshold} shares.", 400

    # Check share tracking for this file FIRST
    expected_shares = {}
    try:
        with open("share_tracking.txt", "r") as f:
            lines = f.readlines()
            # Find most recent tracking entry for this file
            latest_line = None
            for line in reversed(lines):  # Start from end
                if filename in line:
                    latest_line = line
                    break
            
            if latest_line:
                print(f"DEBUG: Found latest share tracking line: {latest_line.strip()}")
                # Extract share mapping from line
                parts = latest_line.strip().split("Share mapping: ")
                if len(parts) > 1:
                    import ast
                    expected_shares = ast.literal_eval(parts[1])
                    print(f"DEBUG: Expected shares from latest tracking: {expected_shares}")
            else:
                print(f"DEBUG: No tracking entry found for file: {filename}")
    except FileNotFoundError:
        print("DEBUG: No share tracking file found")
    except Exception as e:
        print(f"DEBUG: Error reading share tracking: {e}")

    # Reconstruct secret using collected shares directly (order-independent)
    print(f"DEBUG: Shares collected: {shares}")
    
    # Use shares as collected (already in correct order from collection logic)
    reconstructed = reconstruct_secret(shares)
    print(f"DEBUG: Reconstructed secret: {reconstructed}")

    valid = False
    try:
        with open("secrets.txt", "r") as f:
            for line in f:
                if filename in line:
                    # Check if reconstructed secret matches either Secret or OriginalSecret
                    if str(reconstructed) in line:
                        valid = True
                        print(f"DEBUG: Secret validation PASSED - {reconstructed} found in line")
                        break
                    else:
                        print(f"DEBUG: Secret validation FAILED - {reconstructed} not found in line")
    except Exception as e:
        print(f"DEBUG: Error validating secret: {e}")
    print(f"DEBUG: Secret validation result: {valid}")
    if not valid:
        user_email = email

        metrics["failed_download_attempts"].setdefault(user_email, 0)
        metrics["failed_download_attempts"][user_email] += 1

        if metrics["failed_download_attempts"][user_email] > 3:
            metrics["anomalies_detected"] += 1

            # ⏱️ Block for 10 minutes
            blocked_users[user_email] = datetime.now() + timedelta(minutes=10)

            with open("anomaly_log.txt", "a") as f:
                f.write(
                    f"{datetime.now()} - User {user_email} blocked for 10 minutes\n"
                )

            session.clear()
            return redirect("/login")

        return "Invalid shares", 403  
    # Compare with expected shares if available
    if expected_shares:
        print(f"DEBUG: Comparing received shares with expected shares:")
        print(f"DEBUG: IMPORTANT: ANY {threshold} shares from the following will work!")
        for email, expected_share in expected_shares.items():
            # expected_share is now exact share value (no padding)
            received_share = next((share for share in shares if str(share[1]) == expected_share), None)
            if received_share:
                print(f"DEBUG: {email}: Expected {expected_share}, Received {received_share[1]} - {'MATCH' if str(received_share[1]) == expected_share else 'MISMATCH'}")
            else:
                print(f"DEBUG: {email}: Expected {expected_share}, Received NOTHING")
        
        # Show all available shares
        print(f"DEBUG: ALL AVAILABLE SHARES (Any {threshold} will work):")
        for email, expected_share in expected_shares.items():
            print(f"DEBUG:   - {email}: Share {expected_share}")

        # ---- ANOMALY DETECTION: FAILED SECRET RECONSTRUCTION ----
    try:
        # UNWRAP AES
        priv, _ = get_user_rsa_keys(email)
        wrapped = load_wrapped_key(filename, email)
        aes_key = rsa_unwrap_key(wrapped, priv)
        # DECRYPT
        obj = s3.get_object(Bucket=S3_BUCKET_NAME, Key=filename)
        decrypted = aes_decrypt(obj['Body'].read(), aes_key)

        return Response(
            decrypted,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        return f"Error during download: {str(e)}", 500
@app.route("/metrics")
@jwt_required()
def view_metrics():
    return jsonify({
        "Total Uploads": metrics["total_uploads"],
        "Total Download Attempts": metrics["total_downloads"],
        "Failed Reconstructions (per user)": metrics["failed_download_attempts"],
        "Anomalies Detected": metrics["anomalies_detected"]
    })
# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(debug=True)