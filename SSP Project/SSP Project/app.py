from datetime import datetime, timedelta
from configparser import ConfigParser
from mysql.connector import Error
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, send_file
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message
import requests, zipfile, hashlib, os, cryptography.fernet, secrets, bcrypt, pymysql, uuid, mysql.connector, pyotp, qrcode, io
from dotenv import load_dotenv

VALID_ROLES = ['admin', 'doctor', 'nurse', 'patient', 'hr']
ROLE_LEVELS = {'admin': 2, 'doctor': 1, 'nurse': 1, 'patient': 0, 'hr': 1}

load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
# Email config including MAIL_DEFAULT_SENDER
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_USERNAME'),  # Important!
)

mail = Mail(app)

# Serializer for tokens
s = URLSafeTimedSerializer(app.secret_key)

# DB connection (adjust as needed)
mydb = pymysql.connect(
    host="localhost",
    user="root",
    password="mysql",
    database="healthcare_security"
)
mycursor = mydb.cursor(pymysql.cursors.DictCursor)


def get_serializer():
    return s


@app.route('/logout')
def log_out():
    session.clear()
    return render_template('login.html')


def verify_recaptcha(response_token):
    secret_key = "6Ld0r4srAAAAAH_tZwT_CMfT4WLVjqadp-1k6sVS"
    payload = {
        'secret': secret_key,
        'response': response_token
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = r.json()
    return result.get('success', False)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        mycursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
        user = mycursor.fetchone()
        if user:
            token = s.dumps(email, salt='reset-password')
            reset_link = url_for('reset_with_token', token=token, _external=True)

            msg = Message(
                "Reset Your Password",
                recipients=[email],
                body=f"Click the link to reset your password (valid for 15 minutes): {reset_link}"
            )

            try:
                mail.send(msg)
                flash("✅ Password reset email sent. Please check your inbox.", "success")
            except Exception as e:
                print(f"Mail send error: {e}")  # For debugging
                flash("❌ Failed to send email. Please try again later.", "error")
        else:
            flash("❌ Email not found.", "error")
    return render_template('forgot_password.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    s = URLSafeTimedSerializer(app.secret_key)  # or your get_serializer() function
    try:
        email = s.loads(token, salt='reset-password', max_age=900)  # 15 mins expiry
    except SignatureExpired:
        flash("❌ The reset link has expired.", "error")
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash("❌ Invalid reset link.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']

        if new_pw != confirm_pw:
            flash("❌ Passwords do not match.", "error")
            return render_template('reset_password_email_link.html')

        hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        mycursor.execute("UPDATE users SET password_hash=%s WHERE email=%s", (hashed_pw, email))
        mydb.commit()
        flash("✅ Password updated successfully. Please login.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password_email_link.html')


def has_permission(user_role, resource, action):
    sql = "SELECT * FROM permissions WHERE role=%s AND resource=%s AND action=%s"
    mycursor.execute(sql, (user_role, resource, action))
    return mycursor.fetchone() is not None


def can_assign_to(role):
    assigner_role = session.get('user_role')
    sql = "SELECT * FROM permission_assign_rights WHERE assigner_role=%s AND target_role=%s"
    mycursor.execute(sql, (assigner_role, role))
    return mycursor.fetchone() is not None


def get_user_role_level():
    sql = "SELECT role_level FROM users WHERE user_id=%s"
    mycursor.execute(sql, (session.get('user_id'),))
    result = mycursor.fetchone()
    return result['role_level'] if result else 0


def get_role_level(role):
    return ROLE_LEVELS.get(role.strip().lower(), 0)


def check_and_flash_permission(role, resource, action, success_msg, fail_msg):
    if has_permission(role, resource, action):
        flash(success_msg, 'success')
        return True
    else:
        flash(fail_msg, 'error')
        return False


def get_doctors_and_patients():
    mycursor.execute("SELECT user_id, username FROM users WHERE role = 'doctor'")
    doctors = mycursor.fetchall()

    mycursor.execute("SELECT patient_id, name FROM patient_records")
    patients = mycursor.fetchall()

    return doctors, patients


def log_action(user_id, action):
    try:
        ip = request.remote_addr or 'Unknown'
        mycursor.execute(
            "INSERT INTO audit_logs (user_id, action, ip_address) VALUES (%s, %s, %s)",
            (user_id, action, ip)
        )
        mydb.commit()
    except Exception as e:
        print(f"Audit log failed: {str(e)}")


def get_doctor_patients():
    user_id = session.get('user_id')
    now = datetime.now()
    patients = {}

    mycursor.execute("""
        SELECT pr.patient_id, pr.name, pr.diagnosis
        FROM patient_records pr
        JOIN appointments a ON a.patient_id = pr.patient_id
        WHERE a.doctor_id = %s
    """, (user_id,))
    for p in mycursor.fetchall():
        patients[p['patient_id']] = p

    mycursor.execute("""
        SELECT pr.patient_id, pr.name, pr.diagnosis
        FROM patient_records pr
        JOIN temporary_patient_access tpa ON tpa.patient_id = pr.patient_id
        WHERE tpa.doctor_id = %s AND tpa.expires_at > %s
    """, (user_id, now))
    for p in mycursor.fetchall():
        patients[p['patient_id']] = p

    mycursor.execute("""
        SELECT patient_id, name, diagnosis
        FROM patient_records
        WHERE created_by_doctor_id = %s
    """, (user_id,))
    for p in mycursor.fetchall():
        patients[p['patient_id']] = p

    return list(patients.values())


def register_device_for_user(user_id):
    user_agent = request.headers.get('User-Agent')
    ip = request.remote_addr or 'unknown'
    device_name = f"{request.user_agent.platform or 'Unknown'} - {request.user_agent.browser or 'Unknown'}"

    mycursor.execute("""
        SELECT * FROM user_devices 
        WHERE user_id = %s AND user_agent = %s AND ip_address = %s
    """, (user_id, user_agent, ip))
    existing = mycursor.fetchone()

    now = datetime.now()

    if existing:
        if existing.get('revoked'):
            mycursor.execute("""
                UPDATE user_devices 
                SET revoked = FALSE, trusted = FALSE, approved = FALSE, last_login = %s
                WHERE device_id = %s
            """, (now, existing['device_id']))
            flash("⚠️ This previously revoked device is now re-registered (pending approval).", "warning")
            log_action(user_id, "Re-registered a previously revoked device")
        else:
            mycursor.execute("""
                UPDATE user_devices 
                SET last_login = %s 
                WHERE device_id = %s
            """, (now, existing['device_id']))
    else:

        mycursor.execute("""
            INSERT INTO user_devices (user_id, device_name, ip_address, user_agent, trusted, approved, revoked, 
            last_login)
            VALUES (%s, %s, %s, %s, FALSE, FALSE, FALSE, %s)
        """, (user_id, device_name, ip, user_agent, now))

        flash("⚠️ A new device tried to log in and is pending your approval.", "warning")
        log_action(user_id, f"New device registered (pending approval)")

    mydb.commit()


def is_current_device_trusted():
    user_id = session.get('user_id')
    if not user_id:
        return False

    ip = request.remote_addr or 'unknown'
    user_agent = request.headers.get('User-Agent')

    mycursor.execute("""
        SELECT trusted FROM user_devices 
        WHERE user_id = %s AND ip_address = %s AND user_agent = %s
    """, (user_id, ip, user_agent))

    result = mycursor.fetchone()
    return result and result.get('trusted', False)


@app.before_request
def block_untrusted_device():
    public_endpoints = {'static', 'login', 'register'}
    if request.endpoint in public_endpoints or request.endpoint is None:
        return

    role = session.get('user_role')
    user_id = session.get('user_id')

    if role == "doctor" and user_id:
        user_agent = request.headers.get('User-Agent')
        ip = request.remote_addr or 'unknown'

        mycursor.execute("""
            SELECT trusted, approved, revoked FROM user_devices 
            WHERE user_id = %s AND ip_address = %s AND user_agent = %s
        """, (user_id, ip, user_agent))
        device = mycursor.fetchone()

        if not device or device.get("revoked"):
            session.clear()
            flash("❌ Access revoked for this device. Please log in again from a trusted device.", "error")
            return redirect(url_for('login'))

        if not device['trusted'] or not device['approved']:
            session.clear()
            flash("🔒 Access blocked: device is not trusted or not approved.", "error")
            return redirect(url_for('login'))


@app.route('/')
def index():
    role = session.get('user_role')
    if not role:
        return render_template('base.html')

    if role == 'admin':
        return redirect(url_for('view_users'))
    elif role == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    elif role == 'nurse':
        return redirect(url_for('nurse_dashboard'))
    elif role == 'hr':
        return redirect(url_for('hr_appointments'))
    elif role == 'patient':
        flash("✅ Logged in as patient!", "success")
        return render_template('base.html')
    else:
        flash("⚠️ Unknown role", "error")
        return render_template('base.html')


def generate_token(email):
    return s.dumps(email, salt="email-confirm")


def send_verification_email(username, email, raw_password, role):
    hashed_pw = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    role_level = get_role_level(role)

    user_data = {
        'username': username,
        'email': email,
        'password_hash': hashed_pw,
        'role': role,
        'role_level': role_level
    }

    token = s.dumps(user_data, salt='email-confirm')
    link = url_for("confirm_email", token=token, _external=True)

    msg = Message(
        "Verify Your Email",
        recipients=[email],
        body=f"Click this link to verify your account: {link}"
    )

    mail.send(msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response or not verify_recaptcha(recaptcha_response):
            flash("Please complete the reCAPTCHA to verify you are human.", "error")
            return redirect(url_for('register'))

        username = request.form.get('username').strip()
        raw_password = request.form.get('password')
        email = request.form.get('email').strip().lower()
        role = request.form.get('role', '').strip().lower()

        if role not in VALID_ROLES:
            flash("❌ Invalid role selected. Please choose a valid role.", "error")
            return redirect(url_for('register'))

        # Check for duplicate
        mycursor.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
        if mycursor.fetchone():
            flash("❌ Username or Email already exists.", "error")
            return redirect(url_for('register'))

        try:
            send_verification_email(username, email, raw_password, role)
            flash("✅ Check your email to verify your account.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"❌ Failed to send verification email: {str(e)}", "error")
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        data = s.loads(token, salt="email-confirm", max_age=900)  # 15 mins
    except SignatureExpired:
        flash("❌ The verification link has expired.", "error")
        return redirect(url_for('register'))
    except BadSignature:
        flash("❌ Invalid verification link.", "error")
        return redirect(url_for('register'))

    username = data['username']
    email = data['email']
    password_hash = data['password_hash']
    role = data['role']
    role_level = data['role_level']

    # Check again to avoid duplicates
    mycursor.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
    if mycursor.fetchone():
        flash("⚠️ This account has already been verified.", "warning")
        return redirect(url_for('login'))

    mycursor.execute("""
        INSERT INTO users (username, password_hash, role, email, role_level, is_verified)
        VALUES (%s, %s, %s, %s, %s, TRUE)
    """, (username, password_hash, role, email, role_level))

    mydb.commit()
    flash("✅ Email verified! You may now log in.", "success")
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response or not verify_recaptcha(recaptcha_response):
            flash("Please complete the reCAPTCHA to verify you are human.", "error")
            return redirect(url_for('login'))
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # Fetch user info including is_verified
        mycursor.execute(
            "SELECT user_id, password_hash, role, is_verified FROM users WHERE username=%s",
            (username,)
        )
        result = mycursor.fetchone()

        if result:
            # Check if user email is verified
            if not result.get('is_verified'):
                flash("📧 Please verify your email before logging in.", "warning")
                return redirect(url_for('login'))

            # Check password
            if bcrypt.checkpw(password, result['password_hash'].encode('utf-8')):
                user_id = result['user_id']
                user_agent = request.headers.get('User-Agent')
                ip = request.remote_addr or 'unknown'

                # Device check logic (your existing code)
                mycursor.execute("""
                    SELECT device_id, trusted, approved, revoked, last_login
                    FROM user_devices 
                    WHERE user_id = %s AND user_agent = %s AND ip_address = %s
                """, (user_id, user_agent, ip))
                device = mycursor.fetchone()

                if device:
                    if device['revoked']:
                        flash("❌ This device has been revoked. Access denied.", "error")
                        log_action(user_id, "Login attempt from revoked device")
                        return redirect(url_for('login'))

                    if not device['approved']:
                        mycursor.execute("""
                            SELECT device_id, last_login 
                            FROM user_devices 
                            WHERE user_id = %s AND approved = TRUE
                            ORDER BY last_login DESC LIMIT 1
                        """, (user_id,))
                        last_known = mycursor.fetchone()

                        if not last_known or (last_known['last_login'] and datetime.now() - last_known['last_login'] > timedelta(days=7)):
                            mycursor.execute("""
                                UPDATE user_devices 
                                SET approved = TRUE, trusted = TRUE, last_login = NOW()
                                WHERE device_id = %s
                            """, (device['device_id'],))
                            mydb.commit()
                            flash("✅ No active approved device found. This device has been auto-approved.", "success")
                            log_action(user_id, "Device auto-approved due to missing/inactive prior device")
                        else:
                            flash("🔒 This device is not approved. Please log in from an approved device.", "error")
                            log_action(user_id, "Blocked login from unapproved device")
                            return redirect(url_for('login'))

                    elif not device['trusted']:
                        flash("❌ This device is not trusted. Access denied.", "error")
                        log_action(user_id, "Blocked login from untrusted device")
                        return redirect(url_for('login'))

                    mycursor.execute("UPDATE user_devices SET last_login = NOW() WHERE device_id = %s", (device['device_id'],))
                    mydb.commit()

                else:
                    device_name = f"{request.user_agent.platform or 'Unknown'} - {request.user_agent.browser or 'Unknown'}"
                    mycursor.execute("""
                        INSERT INTO user_devices (user_id, device_name, ip_address, user_agent, trusted, approved, revoked, last_login)
                        VALUES (%s, %s, %s, %s, FALSE, FALSE, FALSE, NOW())
                    """, (user_id, device_name, ip, user_agent))
                    mydb.commit()
                    flash("⚠ New device registered. Please approve it from your main device.", "warning")
                    log_action(user_id, "New device login blocked until approved")
                    return redirect(url_for('login'))

                # Successful login: set session and redirect
                session['user_id'] = user_id
                session['user_role'] = result['role']
                session['username'] = username
                log_action(user_id, f"Logged in as {username} ({result['role']})")
                flash(f"✅ Logged in as: {username} ({result['role']})", "success")
                return redirect(url_for('index'))

            else:
                flash("❌ Invalid username or password.", "error")
                return redirect(url_for('login'))

        else:
            flash("❌ Invalid username or password.", "error")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/admin/users')
def view_users():
    if session.get('user_role') != 'admin':
        return "Access Denied"
    mycursor.execute("SELECT * FROM users")
    return render_template('view_users.html', users=mycursor.fetchall())


@app.route('/admin/update_user/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    if session.get('user_role') != 'admin':
        return "Access Denied"

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role'].strip().lower()
        role_level = get_role_level(role)

        mycursor.execute("UPDATE users SET username=%s, email=%s, role=%s, role_level=%s WHERE user_id=%s",
                         (username, email, role, role_level, user_id))
        mydb.commit()
        log_action(session['user_id'], f"Updated user_id={user_id}")
        return redirect(url_for('view_users'))

    mycursor.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))
    return render_template('update_user.html', user=mycursor.fetchone())


@app.route('/admin/delete_user/<int:user_id>')
def delete_user(user_id):
    if session.get('user_role') != 'admin':
        return "Access Denied"
    try:
        mycursor.execute("DELETE FROM audit_logs WHERE user_id = %s", (user_id,))
        mycursor.execute("DELETE FROM shared_patient_links WHERE created_by_doctor_id = %s", (user_id,))
        mycursor.execute("DELETE FROM temporary_patient_access WHERE doctor_id = %s OR granted_by_admin_id = %s",
                         (user_id, user_id))
        mycursor.execute("DELETE FROM appointments WHERE doctor_id = %s", (user_id,))
        mycursor.execute("DELETE FROM user_devices WHERE user_id = %s", (user_id,))
        mycursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        mydb.commit()
        log_action(session['user_id'], f"Deleted user_id={user_id} and dependencies")
        flash("✅ User deleted successfully.", "success")
        mycursor.execute("SELECT 1 FROM users WHERE user_id = %s", (session.get('user_id'),))
        still_exists = mycursor.fetchone()

        if not still_exists:
            session.clear()
            flash("⚠ You deleted your own account. Session ended.", "warning")
            return redirect(url_for('login'))
    except Exception as e:
        mydb.rollback()
        flash(f"❌ Error deleting user: {str(e)}", "error")
    return redirect(url_for('view_users'))


@app.route('/admin/permissions')
def view_permissions():
    if session.get('user_role') != 'admin':
        return "Access Denied"
    mycursor.execute("SELECT DISTINCT role FROM users")
    valid_roles = set(r['role'] for r in mycursor.fetchall())
    mycursor.execute("SELECT * FROM permissions ORDER BY role, resource, action")
    permissions = [p for p in mycursor.fetchall() if p['role'] in valid_roles]
    return render_template('view_permissions.html', permissions=permissions)


@app.route('/admin/add_permission', methods=['GET', 'POST'])
def add_permission():
    if session.get('user_role') != 'admin':
        return "Access Denied"

    if request.method == 'POST':
        role = request.form['role']
        mycursor.execute("SELECT COUNT(*) AS count FROM users WHERE role=%s", (role,))
        if mycursor.fetchone()['count'] == 0:
            return "Only roles from registered users can be used."
        if not can_assign_to(role):
            return "You are not allowed to assign permissions to this role."

        resource = request.form['resource']
        action = request.form['action']
        mycursor.execute("INSERT INTO permissions (role, resource, action) VALUES (%s, %s, %s)",
                         (role, resource, action))
        mydb.commit()
        return redirect(url_for('view_permissions'))

    return render_template('add_permission.html')


@app.route('/admin/update_permission/<int:permission_id>', methods=['GET', 'POST'])
def update_permission(permission_id):
    if session.get('user_role') != 'admin':
        return "Access Denied"

    if request.method == 'POST':
        role = request.form['role']
        resource = request.form['resource']
        action = request.form['action']

        if not can_assign_to(role):
            return "You are not allowed to assign permissions to this role."

        mycursor.execute("""
            SELECT * FROM permissions
            WHERE role = %s AND resource = %s AND action = %s AND permission_id != %s
        """, (role, resource, action, permission_id))
        existing = mycursor.fetchone()

        if existing:
            flash("❌ This permission already exists. Update aborted.", "error")
            return redirect(url_for('update_permission', permission_id=permission_id))

        mycursor.execute("""
            UPDATE permissions
            SET role = %s, resource = %s, action = %s
            WHERE permission_id = %s
        """, (role, resource, action, permission_id))
        mydb.commit()
        log_action(session['user_id'], f"Updated permission_id={permission_id}")
        flash("✅ Permission updated successfully.", "success")
        return redirect(url_for('view_permissions'))

    mycursor.execute("SELECT * FROM permissions WHERE permission_id=%s", (permission_id,))
    return render_template('update_permission.html', perm=mycursor.fetchone())


@app.route('/admin/delete_permission/<int:permission_id>')
def delete_permission(permission_id):
    if session.get('user_role') != 'admin':
        return "Access Denied"
    mycursor.execute("DELETE FROM permissions WHERE permission_id=%s", (permission_id,))
    mydb.commit()
    log_action(session['user_id'], f"Deleted permission_id={permission_id}")
    return redirect(url_for('view_permissions'))


@app.route('/doctor/referral', methods=['GET', 'POST'])
def refer_patient():
    if session.get('user_role') != 'doctor':
        return "Access Denied"

    mycursor.execute("SELECT user_id, username FROM users WHERE role = 'doctor' AND user_id != %s",
                     (session['user_id'],))
    other_doctors = mycursor.fetchall()

    mycursor.execute("""
        SELECT pr.patient_id, pr.name
        FROM patient_records pr
        JOIN appointments a ON a.patient_id = pr.patient_id
        WHERE a.doctor_id = %s
    """, (session['user_id'],))
    own_patients = mycursor.fetchall()

    if request.method == 'POST':
        patient_id = request.form['patient_id']
        referred_to_id = request.form['doctor_id']
        reason = request.form.get('reason', '')

        mycursor.execute("""
            INSERT INTO referrals (patient_id, referred_by_doctor_id, referred_to_doctor_id, reason)
            VALUES (%s, %s, %s, %s)
        """, (patient_id, session['user_id'], referred_to_id, reason))
        mydb.commit()
        log_action(session['user_id'], f"Referred patient {patient_id} to doctor {referred_to_id}")
        flash("✅ Referral submitted for admin approval.", "success")
        return redirect(url_for('doctor_dashboard'))

    return render_template("refer_patient.html", doctors=other_doctors, patients=own_patients)


@app.route('/admin/referrals', methods=['GET', 'POST'])
def admin_referrals():
    if session.get('user_role') != 'admin':
        return "Access Denied"

    if request.method == 'POST':
        referral_id = request.form['referral_id']
        expires_at = request.form['expires_at']

        mycursor.execute("""
            SELECT * FROM referrals WHERE referral_id = %s AND approved = FALSE
        """, (referral_id,))
        referral = mycursor.fetchone()

        if not referral:
            flash("❌ Invalid referral or already approved.", "error")
            return redirect(url_for('admin_referrals'))

        mycursor.execute("""
            UPDATE referrals
            SET approved = TRUE,
                approved_by_admin_id = %s,
                approved_at = NOW(),
                expires_at = %s
            WHERE referral_id = %s
        """, (session['user_id'], expires_at, referral_id))

        mycursor.execute("""
            INSERT INTO temporary_patient_access (doctor_id, patient_id, granted_by_admin_id, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (referral['referred_to_doctor_id'], referral['patient_id'], session['user_id'], expires_at))
        mydb.commit()

        log_action(session['user_id'], f"Approved referral {referral_id} and granted temp access")
        flash("✅ Referral approved and access granted.", "success")
        return redirect(url_for('admin_referrals'))

    mycursor.execute("""
        SELECT r.*, u1.username AS referred_by, u2.username AS referred_to, pr.name AS patient_name
        FROM referrals r
        JOIN users u1 ON r.referred_by_doctor_id = u1.user_id
        JOIN users u2 ON r.referred_to_doctor_id = u2.user_id
        JOIN patient_records pr ON r.patient_id = pr.patient_id
        WHERE approved = FALSE
    """)
    referrals = mycursor.fetchall()
    return render_template("admin_referrals.html", referrals=referrals)


@app.route('/admin/add_temp_access', methods=['GET', 'POST'])
def add_temp_access():
    if session.get('user_role') != 'admin':
        return "Access Denied"

    doctors, patients = get_doctors_and_patients()

    if request.method == 'POST':
        doctor_id = request.form['doctor_id']
        patient_id = request.form['patient_id']
        expires_at = request.form.get('expires_at') or request.form.get('expires_picker')

        try:
            expires_at_dt = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
            if expires_at_dt <= datetime.now():
                flash("❌ Expiry time must be in the future.", "error")
                return render_template('add_temp_access.html', doctors=doctors, patients=patients)

            mycursor.execute("""
                INSERT INTO temporary_patient_access (doctor_id, patient_id, granted_by_admin_id, expires_at)
                VALUES (%s, %s, %s, %s)
            """, (doctor_id, patient_id, session['user_id'], expires_at))
            mydb.commit()

            flash("✅ Temporary access granted successfully.", "success")
            log_action(session['user_id'],
                       f"Granted temp access to doctor_id={doctor_id} for patient_id={patient_id} until {expires_at}")
        except Exception as e:
            mydb.rollback()
            flash(f"❌ Error: {str(e)}", "error")

    return render_template('add_temp_access.html', doctors=doctors, patients=patients)


@app.route('/admin/add_appointment', methods=['GET', 'POST'])
def add_appointment():
    if session.get('user_role') != 'admin':
        return "Access Denied"

    if request.method == 'POST':
        doctor_id = request.form['doctor_id']
        patient_id = request.form['patient_id']
        appointment_date = request.form['appointment_date']

        mycursor.execute("""
            SELECT * FROM appointments
            WHERE doctor_id=%s AND patient_id=%s AND appointment_date=%s
        """, (doctor_id, patient_id, appointment_date))

        if mycursor.fetchone():
            flash("❌ Appointment already exists.", "error")
        else:
            mycursor.execute("""
                INSERT INTO appointments (doctor_id, patient_id, appointment_date)
                VALUES (%s, %s, %s)
            """, (doctor_id, patient_id, appointment_date))
            log_action(session['user_id'],
                       f"Created appointment for doctor_id={doctor_id}, patient_id={patient_id} on {appointment_date}")
            mydb.commit()
            flash("✅ Appointment scheduled successfully.", "success")

        return redirect(url_for('add_appointment'))

    doctors, patients = get_doctors_and_patients()
    return render_template("add_appointment.html", doctors=doctors, patients=patients)


@app.route('/admin/appointments')
def view_appointments():
    if session.get('user_role') != 'admin':
        return "Access Denied"

    mycursor.execute("""
        SELECT a.appointment_id, u.username AS doctor_name, pr.name AS patient_name, a.appointment_date
        FROM appointments a
        JOIN users u ON a.doctor_id = u.user_id
        JOIN patient_records pr ON a.patient_id = pr.patient_id
        ORDER BY a.appointment_date DESC
    """)
    return render_template("view_appointments.html", appointments=mycursor.fetchall())


@app.route('/admin/edit_appointment/<int:appointment_id>', methods=['GET', 'POST'])
def edit_appointment(appointment_id):
    if session.get('user_role') == 'admin':
        flash("❌ Admins are not allowed to edit appointments.", "error")
        return redirect(url_for('view_appointments'))
    return "404 Not Found", 404


@app.route('/admin/delete_appointment/<int:appointment_id>')
def delete_appointment(appointment_id):
    if session.get('user_role') == 'admin':
        flash("❌ Admins are not allowed to delete appointments.", "error")
        return redirect(url_for('view_appointments'))
    return "404 Not Found", 404


@app.route('/admin/audit_logs', methods=['GET', 'POST'])
def view_audit_logs():
    if session.get('user_role') != 'admin':
        return "Access Denied"

    page = int(request.args.get('page', 1))
    per_page = 10
    offset = (page - 1) * per_page
    filters = []
    params = []

    if request.method == 'POST':
        session['log_filters'] = {
            'username': request.form.get('username', ''),
            'role': request.form.get('role', ''),
            'action': request.form.get('action', '')
        }
        return redirect(url_for('view_audit_logs'))

    filters_from_session = session.get('log_filters', {})

    query = """
        SELECT al.log_id, u.username, u.role, al.action, al.timestamp, al.ip_address
        FROM audit_logs al
        JOIN users u ON al.user_id = u.user_id
    """

    if filters_from_session:
        if filters_from_session.get('username'):
            filters.append("u.username LIKE %s")
            params.append(f"%{filters_from_session['username']}%")
        if filters_from_session.get('role'):
            filters.append("u.role = %s")
            params.append(filters_from_session['role'])
        if filters_from_session.get('action'):
            filters.append("al.action LIKE %s")
            params.append(f"%{filters_from_session['action']}%")

    if filters:
        query += " WHERE " + " AND ".join(filters)

    count_query = f"SELECT COUNT(*) as total FROM ({query}) as sub"
    mycursor.execute(count_query, params)
    total = mycursor.fetchone()['total']
    total_pages = (total + per_page - 1) // per_page

    query += " ORDER BY al.timestamp DESC LIMIT %s OFFSET %s"
    mycursor.execute(query, params + [per_page, offset])
    logs = mycursor.fetchall()

    return render_template("audit_logs.html", logs=logs, page=page, total_pages=total_pages)


@app.route('/hr/appointments', methods=['GET', 'POST'])
def hr_appointments():
    if session.get('user_role') != 'hr':
        return "Access Denied"

    if request.method == 'POST':
        if not has_permission('hr', 'appointments', 'create'):
            return "❌ You do not have permission to create appointments."

        doctor_id = request.form['doctor_id']
        patient_id = request.form['patient_id']
        appointment_date = request.form['appointment_date']

        try:
            mycursor.execute("""
                SELECT * FROM appointments
                WHERE doctor_id = %s AND patient_id = %s AND appointment_date = %s
            """, (doctor_id, patient_id, appointment_date))

            if mycursor.fetchone():
                flash("❌ Appointment already exists.", "error")
            else:
                mycursor.execute("""
                    INSERT INTO appointments (doctor_id, patient_id, appointment_date)
                    VALUES (%s, %s, %s)
                """, (doctor_id, patient_id, appointment_date))
                log_action(session['user_id'],
                           f"Created appointment for doctor_id={doctor_id}, patient_id={patient_id} "
                           f"on {appointment_date}")
                mydb.commit()
                flash("✅ Appointment created.", "success")
        except Exception as e:
            mydb.rollback()
            flash(f"❌ Error creating appointment: {str(e)}", "error")

    doctors, patients = get_doctors_and_patients()

    appointments = []
    if has_permission('hr', 'appointments', 'read'):
        mycursor.execute("""
            SELECT a.appointment_id, u.username AS doctor_name, pr.name AS patient_name, a.appointment_date
            FROM appointments a
            JOIN users u ON a.doctor_id = u.user_id
            JOIN patient_records pr ON a.patient_id = pr.patient_id
            ORDER BY a.appointment_date DESC
        """)
        appointments = mycursor.fetchall()

    if appointments:
        log_action(session['user_id'], f"Viewed {len(appointments)} appointments as HR")

    return render_template("hr_appointments.html", doctors=doctors, patients=patients, appointments=appointments)


@app.route('/doctor', methods=['GET', 'POST'])
def doctor_dashboard():
    if session.get('user_role') != 'doctor':
        return "Access Denied"

    result = ""
    user_id = session.get('user_id')
    now = datetime.now()

    patients = {}

    if request.method == 'POST':
        action = request.form['action']
        if has_permission('doctor', 'patient_records', action):
            result = f"{action.capitalize()} action allowed."
        else:
            result = f"{action.capitalize()} action NOT allowed."

    if has_permission('doctor', 'patient_records', 'read'):

        mycursor.execute("""
            SELECT pr.patient_id, pr.name, pr.diagnosis
            FROM patient_records pr
            JOIN appointments a ON a.patient_id = pr.patient_id
            WHERE a.doctor_id = %s
        """, (user_id,))
        for p in mycursor.fetchall():
            patients[p['patient_id']] = p

        mycursor.execute("""
            SELECT pr.patient_id, pr.name, pr.diagnosis
            FROM patient_records pr
            JOIN temporary_patient_access tpa ON tpa.patient_id = pr.patient_id
            WHERE tpa.doctor_id = %s AND tpa.expires_at > %s
        """, (user_id, now))
        for p in mycursor.fetchall():
            patients[p['patient_id']] = p

        mycursor.execute("""
            SELECT patient_id, name, diagnosis
            FROM patient_records
            WHERE created_by_doctor_id = %s
        """, (user_id,))
        for p in mycursor.fetchall():
            patients[p['patient_id']] = p

    else:
        flash("❌ You do not have permission to view patient records.", "error")

    if patients:
        log_action(user_id, f"Viewed {len(patients)} patient records as doctor")

    return render_template("doctor.html", result=result, message=result, patients=list(patients.values()))


@app.route('/nurse', methods=['GET', 'POST'])
def nurse_dashboard():
    if session.get('user_role') != 'nurse':
        return "Access Denied"

    result = ""
    patients = []

    if request.method == 'POST':
        action = request.form['action']
        if has_permission('nurse', 'patient_records', action):
            result = f"{action.capitalize()} action allowed."
        else:
            result = f"{action.capitalize()} action NOT allowed."

    if has_permission('nurse', 'patient_records', 'read'):
        nurse_id = session.get('user_id')
        today = datetime.today().date()

        mycursor.execute("""
                         SELECT pr.patient_id, pr.name, pr.diagnosis
                         FROM patient_records pr
                                  JOIN appointments a ON a.patient_id = pr.patient_id
                         WHERE a.appointment_date = %s
                         """, (today,))

        patients = mycursor.fetchall()

    else:
        flash("❌ You do not have permission to view patient records.", "error")

    if patients:
        log_action(session['user_id'], f"Viewed {len(patients)} patient records as nurse")

    return render_template("nurse.html", result=result, message=result, patients=patients)


@app.route('/doctor/create', methods=['POST'])
def create_patient():
    if session.get('user_role') != 'doctor':
        return redirect(url_for('doctor_dashboard'))
    if not has_permission('doctor', 'patient_records', 'create'):
        return render_template("doctor.html", message="Permission Denied", patients=[])

    name = request.form['name']
    diagnosis = request.form['diagnosis']
    doctor_id = session['user_id']

    try:
        mycursor.execute(
            "INSERT INTO patient_records (name, diagnosis, created_by_doctor_id) VALUES (%s, %s, %s)",
            (name, diagnosis, doctor_id)
        )
        mydb.commit()
        log_action(doctor_id, f"Created new patient '{name}' without linking to appointment (HR required)")
        flash("✅ Patient created successfully.", "success")
    except Exception as e:
        mydb.rollback()
        flash(f"❌ Error creating patient: {str(e)}", "error")

    patients = get_doctor_patients()
    return render_template("doctor.html", message="Patient created successfully", patients=patients)


@app.route('/doctor/update', methods=['POST'])
def update_patient():
    if session.get('user_role') != 'doctor':
        return redirect(url_for('doctor_dashboard'))
    if not has_permission('doctor', 'patient_records', 'update'):
        return render_template("doctor.html", message="Permission Denied", patients=[])

    try:
        patient_id = int(request.form['patient_id'])
        diagnosis = request.form['diagnosis']

        mycursor.execute("UPDATE patient_records SET diagnosis=%s WHERE patient_id=%s", (diagnosis, patient_id))
        mydb.commit()
        log_action(session['user_id'], f"Updated patient_id={patient_id} diagnosis")
        flash("✅ Patient record updated successfully.", "success")
    except Exception as e:
        mydb.rollback()
        flash(f"❌ Error updating patient: {str(e)}", "error")

    patients = get_doctor_patients()
    return render_template("doctor.html", message="Patient record updated successfully", patients=patients)


@app.route('/nurse/update', methods=['POST'])
def nurse_update():
    if session.get('user_role') != 'nurse':
        return redirect(url_for('nurse_dashboard'))
    if not has_permission('nurse', 'patient_records', 'update'):
        return render_template("nurse.html", message="Permission Denied", patients=[])

    try:
        patient_id = int(request.form['patient_id'])
    except ValueError:
        return render_template("nurse.html", message="Invalid Patient ID", patients=[])

    diagnosis = request.form['diagnosis']
    mycursor.execute("UPDATE patient_records SET diagnosis=%s WHERE patient_id=%s", (diagnosis, patient_id))
    mydb.commit()
    log_action(session['user_id'], f"Updated patient_id={patient_id} diagnosis")  

    patients = []
    if has_permission('nurse', 'patient_records', 'read'):
        mycursor.execute("SELECT patient_id, name, diagnosis FROM patient_records")
        patients = mycursor.fetchall()

    return render_template("nurse.html", message="Patient record updated successfully", patients=patients)


def ensure_appointments_table_exists():
    mycursor.execute("SHOW TABLES LIKE 'appointments'")
    result = mycursor.fetchone()
    if not result:
        print("⛑️ Creating missing 'appointments' table...")
        mycursor.execute("""
            CREATE TABLE IF NOT EXISTS appointments (
                appointment_id INT AUTO_INCREMENT PRIMARY KEY,
                doctor_id INT NOT NULL,
                patient_id INT NOT NULL,
                appointment_date DATE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (doctor_id) REFERENCES users(user_id),
                FOREIGN KEY (patient_id) REFERENCES patient_records(patient_id),
                UNIQUE KEY unique_appointment (doctor_id, patient_id, appointment_date)
            )
        """)
        mydb.commit()


@app.route('/doctor/patient/<int:patient_id>')
def view_patient_detail(patient_id):
    if session.get('user_role') != 'doctor':
        return "Access Denied"

    user_id = session.get('user_id')
    now = datetime.now()

    mycursor.execute("""
        SELECT COUNT(*) as count FROM (
            SELECT 1
            FROM appointments
            WHERE doctor_id = %s AND patient_id = %s
            UNION
            SELECT 1
            FROM temporary_patient_access
            WHERE doctor_id = %s AND patient_id = %s AND expires_at > %s
        ) AS access_check
    """, (user_id, patient_id, user_id, patient_id, now))

    if mycursor.fetchone()['count'] == 0:
        flash("❌ You do not have access to this patient's record.", "error")
        return redirect(url_for('doctor_dashboard'))

    mycursor.execute("SELECT * FROM patient_records WHERE patient_id = %s", (patient_id,))
    patient = mycursor.fetchone()

    mycursor.execute("""
        SELECT visit_date, checkup_result, doctor_notes, created_at
        FROM patient_medical_history
        WHERE patient_id = %s
        ORDER BY visit_date DESC
    """, (patient_id,))
    history = mycursor.fetchall()

    log_action(user_id, f"Viewed detailed record of patient_id={patient_id}")
    return render_template("patient_detail.html", patient=patient, history=history)


@app.route('/nurse/patient/<int:patient_id>')
def view_patient_detail_nurse(patient_id):
    if session.get('user_role') != 'nurse':
        return "Access Denied"

    user_id = session.get('user_id')
    today = datetime.today().date()

    mycursor.execute("""
        SELECT COUNT(*) as count
        FROM appointments
        WHERE patient_id = %s AND appointment_date = %s
    """, (patient_id, today))

    if mycursor.fetchone()['count'] == 0:
        flash("❌ You do not have access to this patient's record.", "error")
        return redirect(url_for('nurse_dashboard'))

    mycursor.execute("SELECT * FROM patient_records WHERE patient_id = %s", (patient_id,))
    patient = mycursor.fetchone()

    mycursor.execute("""
        SELECT visit_date, checkup_result, doctor_notes, created_at
        FROM patient_medical_history
        WHERE patient_id = %s
        ORDER BY visit_date DESC
    """, (patient_id,))
    history = mycursor.fetchall()

    log_action(user_id, f"Nurse viewed patient_id={patient_id}")
    return render_template("nurse_patient_detail.html", patient=patient, history=history)


@app.route('/doctor/share_link/<int:patient_id>')
def generate_share_link(patient_id):
    if session.get('user_role') != 'doctor':
        return "Access Denied"

    try:
        expires_minutes = int(request.args.get('expires', 5))
        if expires_minutes <= 0 or expires_minutes > 1440:  # limit to 24h max
            flash("⚠️ Expiry must be between 1 and 1440 minutes (24h)", "error")
            return redirect(url_for('view_patient_detail', patient_id=patient_id))
    except ValueError:
        flash("⚠️ Invalid expiry value", "error")
        return redirect(url_for('view_patient_detail', patient_id=patient_id))

    link_id = secrets.token_hex(32)
    now = datetime.now().replace(microsecond=0)
    expires_at = now + timedelta(minutes=expires_minutes)

    mycursor.execute("""
        INSERT INTO shared_patient_links (link_id, patient_id, created_by_doctor_id, expires_at)
        VALUES (%s, %s, %s, %s)
    """, (link_id, patient_id, session['user_id'], expires_at))
    mydb.commit()

    share_url = url_for('access_shared_link', link_id=link_id, _external=True)
    flash(f"📤 Link generated (valid for {expires_minutes} min): {share_url}", "success")
    log_action(session['user_id'], f"Generated share link for patient_id={patient_id} (expires in {expires_minutes}m)")
    return redirect(url_for('view_patient_detail', patient_id=patient_id))


@app.route('/doctor/share_link_ui/<int:patient_id>', methods=['POST'])
def share_link_ui(patient_id):
    if session.get('user_role') != 'doctor':
        return "Access Denied"

    try:
        expires_minutes = int(request.form.get('expires', 5))
        if expires_minutes <= 0 or expires_minutes > 1440:
            flash("⚠️ Expiry must be between 1 and 1440 minutes (24h)", "error")
            return redirect(url_for('doctor_dashboard'))
    except ValueError:
        flash("⚠️ Invalid expiry value", "error")
        return redirect(url_for('doctor_dashboard'))

    link_id = secrets.token_hex(32)
    now = datetime.now().replace(microsecond=0)
    expires_at = now + timedelta(minutes=expires_minutes)

    mycursor.execute("""
        INSERT INTO shared_patient_links (link_id, patient_id, created_by_doctor_id, expires_at)
        VALUES (%s, %s, %s, %s)
    """, (link_id, patient_id, session['user_id'], expires_at))
    mydb.commit()

    share_url = url_for('access_shared_link', link_id=link_id, _external=True)
    flash("📋 Link generated and ready to copy below!", "success")
    log_action(session['user_id'], f"Generated link for patient_id={patient_id} via POST UI")

    return render_template("doctor.html", message="Link created", patients=get_doctor_patients(), copied_link=share_url)


@app.route('/shared/<link_id>')
def access_shared_link(link_id):

    mycursor.execute("""
        SELECT s.link_id, s.patient_id, s.created_by_doctor_id, s.expires_at, s.is_used,
               pr.name, pr.diagnosis
        FROM shared_patient_links s
        JOIN patient_records pr ON pr.patient_id = s.patient_id
        WHERE s.link_id = %s
    """, (link_id,))
    record = mycursor.fetchone()

    if not record:
        return "❌ Invalid or expired link."

    expires_at = record['expires_at']

    if not isinstance(expires_at, datetime):
        try:
            expires_at = datetime.strptime(str(expires_at).split('.')[0], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return "⛔ Invalid datetime format from DB"

    if record['is_used']:
        return "⛔ This link has already been used."

    if expires_at < datetime.now():
        return "⏳ Link has expired."

    mycursor.execute("UPDATE shared_patient_links SET is_used = TRUE WHERE link_id = %s", (link_id,))
    mydb.commit()

    mycursor.execute("""
        SELECT visit_date, checkup_result, doctor_notes, created_at
        FROM patient_medical_history
        WHERE patient_id = %s
        ORDER BY visit_date DESC
    """, (record['patient_id'],))
    history = mycursor.fetchall()

    log_action(record['created_by_doctor_id'], f"Viewed shared link for patient_id={record['patient_id']}")

    return render_template("shared_patient_view.html", patient=record, history=history, now=datetime.now())


@app.route('/hr/delete_appointment/<int:appointment_id>', methods=['POST'])
def delete_appointment_hr(appointment_id):
    if session.get('user_role') != 'hr':
        return "Access Denied"

    if not has_permission('hr', 'appointments', 'delete'):
        flash("❌ You do not have permission to delete appointments.", "error")
        return redirect(url_for('hr_appointments'))

    try:
        mycursor.execute("DELETE FROM appointments WHERE appointment_id = %s", (appointment_id,))
        mydb.commit()
        log_action(session['user_id'], f"HR deleted appointment_id={appointment_id}")
        flash("✅ Appointment deleted successfully.", "success")
    except Exception as e:
        mydb.rollback()
        flash(f"❌ Error deleting appointment: {str(e)}", "error")

    return redirect(url_for('hr_appointments'))


@app.route('/doctor/devices', methods=['GET', 'POST'])
def doctor_devices():
    if session.get('user_role') != 'doctor':
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        device_id = request.form.get('device_id')
        action = request.form.get('action')

        if action == 'delete':
            mycursor.execute("""
                UPDATE user_devices
                SET trusted = FALSE, approved = FALSE, revoked = TRUE
                WHERE device_id = %s AND user_id = %s
            """, (device_id, user_id))
            flash("✅ Device access revoked successfully.", "success")

        elif action == 'approve':
            mycursor.execute("""
                UPDATE user_devices SET approved = TRUE, trusted = TRUE
                WHERE device_id = %s AND user_id = %s
            """, (device_id, user_id))
            flash("✅ Device approved and trusted!", "success")

        mydb.commit()

    mycursor.execute("""
        SELECT * FROM user_devices WHERE user_id = %s ORDER BY last_login DESC
    """, (user_id,))
    devices = mycursor.fetchall()

    return render_template("doctor_devices.html", devices=devices)


class HealthcareStaffBackup:
    def __init__(self):
        self.config = ConfigParser()
        self.config.read('config.ini')

        self.encryption_key = self._get_encryption_key()
        self.cipher = cryptography.fernet.Fernet(self.encryption_key)

        self.backup_dir = self.config.get('Backup', 'directory', fallback='backups')
        os.makedirs(self.backup_dir, exist_ok=True)

    def _get_encryption_key(self):
        key_file = 'encryption.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = cryptography.fernet.Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key

    def _connect_db(self):
        try:
            connection = mysql.connector.connect(
                host=self.config.get('Database', 'host', fallback='localhost'),
                user=self.config.get('Database', 'user', fallback='root'),
                password=self.config.get('Database', 'password', fallback=''),
                database=self.config.get('Database', 'database', fallback='healthcare_staff')
            )
            return connection
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            raise

    def create_backup(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f'staff_backup_{timestamp}'

        temp_files = []
        try:
            sql_file = f'{backup_name}.sql'
            temp_files.append(sql_file)

            with self._connect_db() as conn:
                cursor = conn.cursor(dictionary=True)

                cursor.execute("SHOW TABLES")
                tables = [table['Tables_in_' + self.config.get('Database', 'database')] for table in cursor.fetchall()]

                with open(sql_file, 'w') as f:
                    cursor.execute("SELECT VERSION()")
                    mysql_version = cursor.fetchone()['VERSION()']
                    f.write(f"-- MySQL Backup\n-- Version: {mysql_version}\n\n")

                    for table in tables:
                        cursor.execute(f"SHOW CREATE TABLE {table}")
                        create_table = cursor.fetchone()['Create Table']
                        f.write(f"{create_table};\n\n")

                        cursor.execute(f"SELECT * FROM {table}")
                        rows = cursor.fetchall()

                        if rows:
                            columns = rows[0].keys()
                            f.write(f"INSERT INTO {table} ({', '.join(columns)}) VALUES\n")

                            for i, row in enumerate(rows):
                                values = []
                                for value in row.values():
                                    if value is None:
                                        values.append("NULL")
                                    elif isinstance(value, (int, float)):
                                        values.append(str(value))
                                    else:
                                        values.append(f"""'{str(value).replace("'", "''")}'""")

                                f.write(f"({', '.join(values)})")
                                if i < len(rows) - 1:
                                    f.write(",\n")
                                else:
                                    f.write(";\n\n")

            with open(sql_file, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            meta_file = f'{backup_name}.meta'
            temp_files.append(meta_file)
            with open(meta_file, 'w') as f:
                f.write(f"backup_time={timestamp}\n")
                f.write(f"database_version={mysql_version}\n")
                f.write(f"sha256_hash={file_hash}\n")
                f.write(f"created_by={os.getlogin()}\n")

            backup_path = os.path.join(self.backup_dir, f'{backup_name}.zip.enc')
            with zipfile.ZipFile('temp.zip', 'w') as zipf:
                for file in temp_files:
                    zipf.write(file)

            with open('temp.zip', 'rb') as f:
                encrypted_data = self.cipher.encrypt(f.read())

            with open(backup_path, 'wb') as f:
                f.write(encrypted_data)

            print(f"Backup created successfully: {backup_path}")
            return backup_path

        finally:
            for file in temp_files:
                if os.path.exists(file):
                    os.remove(file)
            if os.path.exists('temp.zip'):
                os.remove('temp.zip')

    def list_backups(self):
        backups = []
        for file in os.listdir(self.backup_dir):
            if file.endswith('.zip.enc'):
                backups.append(file)
        return sorted(backups)

    def restore_backup(self, backup_file):
        backup_path = os.path.join(self.backup_dir, backup_file)

        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup file not found: {backup_file}")

        with open(backup_path, 'rb') as f:
            decrypted_data = self.cipher.decrypt(f.read())

        with open('temp_restore.zip', 'wb') as f:
            f.write(decrypted_data)

        extracted_files = []
        try:
            with zipfile.ZipFile('temp_restore.zip', 'r') as zipf:
                extracted_files = zipf.namelist()
                zipf.extractall()

            sql_files = [f for f in extracted_files if f.endswith('.sql')]
            if not sql_files:
                raise ValueError("No SQL file found in backup")

            sql_file = sql_files[0]

            meta_files = [f for f in extracted_files if f.endswith('.meta')]
            if meta_files:
                with open(meta_files[0], 'r') as f:
                    meta_data = dict(line.strip().split('=') for line in f)

                with open(sql_file, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()

                if current_hash != meta_data.get('sha256_hash'):
                    raise ValueError("Backup integrity check failed - hashes don't match")

            with self._connect_db() as conn:
                cursor = conn.cursor()

                with open(sql_file, 'r') as f:
                    sql_commands = f.read().split(';')
                    for command in sql_commands:
                        if command.strip():
                            try:
                                cursor.execute(command)
                            except Error as e:
                                print(f"Error executing command: {e}")
                                conn.rollback()
                                raise
                    conn.commit()

            print(f"Successfully restored database from {backup_file}")
            return True

        finally:
            if os.path.exists('temp_restore.zip'):
                os.remove('temp_restore.zip')
            for file in extracted_files:
                if os.path.exists(file):
                    os.remove(file)


backup_system = HealthcareStaffBackup()


@app.route('/backup')
def backup():
    if session.get('user_role') != 'hr' and session.get('user_role') != 'admin':
        return "Access Denied"
    backups = backup_system.list_backups()
    return render_template('backup.html', backups=backups)


@app.route('/create_backup', methods=['POST'])
def create_backup_route():
    recaptcha_response = request.form.get('g-recaptcha-response')
    if not recaptcha_response or not verify_recaptcha(recaptcha_response):
        flash("Please complete the reCAPTCHA to verify you are human.", "error")
        return redirect(url_for('backup'))
    try:
        backup_file = backup_system.create_backup()
        flash(f"Backup created successfully: {backup_file}", "success")
    except Exception as e:
        flash(f"Backup failed: {str(e)}", "error")
    return redirect(url_for('backup'))


@app.route('/restore_backup', methods=['POST'])
def restore_backup_route():
    backup_file = request.form.get('backup_file')
    try:
        if backup_system.restore_backup(backup_file):
            flash(f"Successfully restored from {backup_file}", "success")
    except Exception as e:
        flash(f"Restore failed: {str(e)}", "error")
    return redirect(url_for('backup'))


@app.route('/download_backup/<filename>')
def download_backup(filename):
    return send_from_directory(backup_system.backup_dir, filename, as_attachment=True)


UPLOAD_FOLDER = os.path.join(os.getcwd(), "healthcare_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
APPROVED_STAFF_IDS = {'doctor', 'nurse', 'admin'}


def is_authorized_staff(staff_id):
    return staff_id in APPROVED_STAFF_IDS


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_healthcare_content(file_stream, filename, staff_id):
    ext = filename.rsplit('.', 1)[1].lower()
    file_stream.seek(0)
    header = file_stream.read(32)
    file_stream.seek(0)

    valid = True
    if ext == 'png' and not header.startswith(b'\x89PNG'):
        valid = False
    elif ext in ('jpg', 'jpeg') and not header.startswith(b'\xFF\xD8\xFF'):
        valid = False
    elif ext == 'gif' and not header.startswith(b'GIF87a') and not header.startswith(b'GIF89a'):
        valid = False
    elif ext == 'pdf' and not header.startswith(b'%PDF'):
        valid = False
    elif ext == 'txt':
        try:
            file_stream.read().decode('utf-8')
            file_stream.seek(0)
        except UnicodeDecodeError:
            valid = False

    if valid:
        file_hash = hashlib.sha256(file_stream.read()).hexdigest()
        file_stream.seek(0)
        try:
            log_path = os.path.join(UPLOAD_FOLDER, 'upload_log.txt')
            with open(log_path, 'a') as log:
                log.write(f"Staff {staff_id} uploaded {filename} with hash {file_hash}\n")
        except Exception as e:
            print(f"Failed to write to log: {str(e)}")
        return True
    return False


def save_healthcare_upload(file, staff_id):
    if not file:
        return None, "No file provided"

    filename = secure_filename(file.filename)
    if not filename:
        return None, "Invalid filename"

    if not allowed_file(filename):
        return None, "File type not permitted"

    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE:
        return None, "File exceeds size limit"

    if not validate_healthcare_content(file, filename, staff_id):
        return None, "File content validation failed"

    unique_name = f"{staff_id}{uuid.uuid4().hex[:8]}{filename}"
    save_path = os.path.join(UPLOAD_FOLDER, unique_name)

    try:
        file.seek(0)
        with open(save_path, 'wb') as f:
            f.write(file.read())
        return unique_name, None
    except Exception as e:
        return None, f"Upload failed: {str(e)}"


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if (session.get('user_role') != 'doctor' and session.get('user_role') != 'nurse' and session.get('user_role') != 'hr'
            and session.get('user_role') != 'admin'):
        return "Access Denied"
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response or not verify_recaptcha(recaptcha_response):
            flash("Please complete the reCAPTCHA to verify you are human.", "error")
            return redirect(url_for('upload_file'))
        file = request.files.get('file')
        user = session.get('username', 'unknown')
        saved_name, error = save_healthcare_upload(file, user)
        if error:
            flash(f"❌ Upload failed: {error}", "error")
        else:
            flash(f"✅ Upload successful! Saved as: {saved_name}", "success")
    return render_template('upload_file.html')


if __name__ == '__main__':
    ensure_appointments_table_exists()
    app.run(debug=True, host="0.0.0.0", port=5000)
