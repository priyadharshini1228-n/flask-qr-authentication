import traceback
import io
import uuid
import re
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, send_file, abort, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from cryptography.fernet import Fernet
from flask_cors import CORS


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong key

# Database Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Spm@12345'
app.config['MYSQL_DB'] = 'mydb'
app.config['ADMIN_SECRET_KEY'] = 'Admin_Cosmo'

mysql = MySQL(app)

# ---------------------- Decorators ----------------------

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('loggedin') or session.get('is_admin') != 1:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ---------------------- LOGIN ----------------------

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM login_detail WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account and check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['id'] = account['user_id']
            session['username'] = account['username']
            session['is_admin'] = account['is_admin']
            print(f"[LOGIN] {account['username']} | Admin: {account['is_admin']}")

            # ✅ Redirect based on admin status
            if session['is_admin'] == 1:
                return redirect(url_for('dashboard'))
            else:
                return render_template('index.html', msg='Logged in successfully!')
        else:
            msg = 'Incorrect username or password!'

    return render_template('login.html', msg=msg)


# ---------------------- LOGOUT ----------------------

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------------------- REGISTER ----------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        device_from = request.headers.get('user-agent')
        is_admin = 0
        admin_key = request.form.get('admin_key')
        if admin_key == 'your_admin_secret_key':
            is_admin = 1

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)


        try:
            if not username or not password or not email:
                msg = 'Please fill out the form!'
            elif not re.match(r'[A-Za-z0-9]+$', username):
                msg = 'Username must contain only letters and numbers!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
            else:
                cursor.execute('SELECT * FROM register_details WHERE username = %s', (username,))
                account = cursor.fetchone()

                if account:
                    msg = 'Account already exists!'
                else:
                    hashed_pw = generate_password_hash(password)
                    cursor.execute(
                        'INSERT INTO register_details (username, password, email_id, device_from, is_admin) VALUES (%s,%s,%s,%s,%s)',
                        (username, hashed_pw, email, device_from, is_admin)
                    )
                    mysql.connection.commit()
                    msg = 'You have successfully registered!'
        except Exception as e:
            traceback.print_exc()
            msg = f'Registration failed: {e}'
    return render_template('register.html', msg=msg)

# ---------------------- USER FORM ----------------------

@app.route('/user_form', methods=['GET', 'POST'])
def user_form():
    FERNET_KEY = b'RkM1tBaCso8pXjxjYL7Nc54AuZmmcuL3EeBI9CjjwV0='
    fernet = Fernet(FERNET_KEY)
    msg = ''
    user_id = None
    if request.method == 'POST':
        fname = request.form['fname']
        username = request.form['username']
        lname = request.form['lname']
        gender = request.form['gender']
        contact_number = request.form['contact_number']
        email_id = request.form['email_id']
        address = request.form['address']
        device_from = request.headers.get('user-agent')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT user_id FROM login_detail WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            user_id = account['user_id']
            try:
                auth_token = str(uuid.uuid4())
                # Step 1: Create raw string and encrypt it
                raw_data = f"user_id:{user_id}|auth_token:{auth_token}"
                encrypted_data= fernet.encrypt(f"user_id:{user_id}|auth_token:{auth_token}".encode()).decode()

                #qr_data = f"user_id:{user_id}|auth_token:{auth_token}"
                qr_img = qrcode.make(encrypted_data)

                img_io = io.BytesIO()
                qr_img.save(img_io, format='PNG')
                img_io.seek(0)
                qr_blob = img_io.read()

                cursor.execute(
                    '''INSERT INTO user_detail 
                    (user_id, fname, contact_number, qr, auth_token, gender, email_id, address, lname, device_from)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                    (user_id, fname, contact_number, qr_blob, auth_token, gender, email_id, address, lname, device_from)
                )
                mysql.connection.commit()
                msg = 'Form submitted and QR stored successfully!'
            except Exception as e:
                traceback.print_exc()
                msg = 'Form submission failed: ' + str(e)
        else:
            msg = 'User not found!'

    return render_template('user_form.html', msg=msg, user_id=user_id)

# ---------------------- VIEW QR PAGE ----------------------

@app.route('/view_qr')
def view_qr():
    user_id = request.args.get('user_id', type=int)

    if not session.get('loggedin'):
        return 'Unauthorized', 403
    if session.get('id') != user_id and session.get('is_admin') != 1:
        return 'Unauthorized', 403

    return render_template('view_qr.html', user_id=user_id)

@app.route('/qr/<int:user_id>')
def get_qr(user_id):
    if not session.get('loggedin'):
        return 'Unauthorized', 403
    if session.get('id') != user_id and session.get('is_admin') != 1:
        return 'Unauthorized', 403

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT qr FROM user_detail WHERE user_id = %s", (user_id,))
    result = cursor.fetchone()

    if result and result['qr']:
        return send_file(io.BytesIO(result['qr']), mimetype='image/png')
    return 'QR Code not found', 404

# ---------------------- ADMIN DASHBOARD ----------------------

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard_view():
        section = request.args.get('section')

        if section == 'reports':
            username = request.args.get('username', '')
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            log_type = request.args.get('log_type')

            query = """
                SELECT r.user_id, r.username, r.email_id, r.is_admin, e.log_type, e.entry_time
                FROM register_details r
                LEFT JOIN entry_logs e ON r.user_id = e.user_id
                WHERE 1=1
            """

            filters = []

            if username:
                query += " AND (r.username LIKE %s OR r.email_id LIKE %s)"
                filters.extend(['%' + username + '%', '%' + username + '%'])

            if start_date:
                query += " AND (e.entry_time IS NULL OR e.entry_time >= %s)"
                filters.append(start_date)

            if end_date:
                query += " AND (e.entry_time IS NULL OR e.entry_time <= %s)"
                filters.append(end_date)

            if log_type:
                query += " AND e.log_type = %s"
                filters.append(log_type)

            query += " ORDER BY COALESCE(e.entry_time, NOW()) DESC"

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(query, filters)
            logs = cursor.fetchall()

            return render_template('admin_dashboard_view.html', logs=logs)

        return render_template('admin_dashboard_view.html')


@app.route('/admin_authentication')
@admin_required
def admin_authentication():
    return render_template('gate_scan.html')  # ← Your HTML is in gate_scan.html


# ---------------------- QR SCANNER PAGE ----------------------

@app.route('/scan_gate')
def scan_gate():
    return render_template('gate_scan.html')
FERNET_KEY = b'RkM1tBaCso8pXjxjYL7Nc54AuZmmcuL3EeBI9CjjwV0='
fernet = Fernet(FERNET_KEY)

@app.route('/verify_qr', methods=['POST'])
def verify_qr():
    qr_data = request.form.get('qr_data')
    print(f"Received QR data: {qr_data}")

    if not qr_data:
        return jsonify({"success": False, "message": "No QR data received."}), 400

    try:
        decrypted = fernet.decrypt(qr_data.encode()).decode()
    except Exception as e:
        print("❌ Decryption failed:", e)
        msg="Invalid or unencrypted QR code"
        #return jsonify({"success": False, "message": f"Invalid or unencrypted QR code: {str(e)}"}), 400
        return (msg)
    match = re.search(r"user_id:(\d+)\|auth_token:([\w\-]+)", decrypted)
    if not match:
        return jsonify({"success": False, "message": "Invalid QR data format."}), 400

    user_id = int(match.group(1))
    auth_token = match.group(2)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM user_detail WHERE user_id = %s AND auth_token = %s", (user_id, auth_token))
    user = cursor.fetchone()

    if user:
        cursor.execute("INSERT INTO entry_logs (user_id) VALUES (%s)", (user_id,))
        mysql.connection.commit()
        msg= "User exists. You are allowed to enter"
       # return jsonify({"success": True, msg="msg"}), 200
        return msg

    return jsonify({"success": False, "message": "❌ Invalid QR or user not found"}), 401

# ---------------------- Main ----------------------
CORS(app)
if __name__ == '__main__':
    app.run(debug=True)
