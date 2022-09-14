from decimal import Decimal
from io import BytesIO
from .utils.interact_db import *
import pyqrcode
import logging
import ipaddress
from flask import Blueprint, redirect, url_for, render_template, request, session, abort, jsonify
from flask_login import login_required, login_user, logout_user
from webportal import flask_bcrypt, login_manager
from webportal.models.Transferee import *
from .forms import *
from .utils.messaging import *
from .utils.email_helper import *
from functools import wraps

views = Blueprint('views', __name__)
TWO_PLACES = Decimal(10) ** -2


def check_email_verification(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.email_verified is False:
            return redirect(url_for('views.unverified_email'))
        return func(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@views.route('/', methods=['GET'])
def home():
    if current_user.is_authenticated:
        msg_data = load_nav_messages()
        return render_template('home.html', title="Home Page", msg_data=msg_data)
    return render_template('home.html', title="Home Page")


@views.route('/about', methods=['GET'])
def about():
    if current_user.is_authenticated:
        msg_data = load_nav_messages()
        return render_template('home.html', title="Home Page", msg_data=msg_data)
    return render_template('about.html', title="About")


@views.route('/register', methods=['GET', 'POST'])
def register():
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))
        return redirect(url_for('views.dashboard'))
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        check = User.query.filter_by(username=username).first()
        if check is not None:
            return render_template('register.html', title="Register", form=form,
                                   register_error="Username already in use")
        firstname = form.firstname.data
        lastname = form.lastname.data
        address = form.address.data
        email = form.email.data
        check = User.query.filter_by(email=email).first()
        if check is not None:
            return render_template('register.html', title="Register", form=form, register_error="Email already in use")
        mobile = form.mobile.data
        check = User.query.filter_by(mobile=mobile).first()
        if check is not None:
            return render_template('register.html', title="Register", form=form, register_error="Mobile already in use")
        nric = form.nric.data.upper()
        check = User.query.filter_by(nric=nric).first()
        if check is not None:
            return render_template('register.html', title="Register", form=form,
                                   register_error="Identification No. already in use")
        dob = form.dob.data
        if dob > date.today():
            return render_template('register.html', title="Register", form=form,
                                   register_error="Invalid date")
        password = flask_bcrypt.generate_password_hash(form.password.data)
        token = generate_token(email)
        new_user = User(username, firstname, lastname, address, email, mobile, nric, dob, password, None, token)
        add_db(new_user)

        # Logging.
        logger = logging.getLogger('user_activity_log')
        logger.info(f"src_ip {ip_source} -> {username} user account created")

        user = User.query.filter_by(username=username).first()

        # Create a bank acc for the newly created user.
        random_gen = SystemRandom()
        acc_number = "".join([str(random_gen.randrange(9)) for i in range(10)])
        welcome_amt = random_gen.randrange(1000, 10000)
        new_message = Message("HX-Bank", welcome_msg(welcome_amt), user.id)
        add_db_no_close(new_message)
        new_account = Account(acc_number, user.id, welcome_amt)

        # Logging
        logger.info(f"src_ip {ip_source} -> Bank acc {acc_number} created and linked to {username}")

        add_db(new_account)
        session['username'] = username
        confirm_url = url_for('views.confirm_email', token=token, _external=True)
        html = render_template('/email_templates/activate.html', confirm_url=confirm_url)
        subject = "HX-Bank - Email Verification"
        send_email(email, subject, html)

        # Return OTP setup page.
        return redirect(url_for("views.otp_setup"))
    return render_template('register.html', title="Register", form=form)


@views.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
        user = User.query.filter_by(email=email).first()
        if user.email_token != token:
            abort(404)
        elif user.email_verified:
            return redirect(url_for('views.login'))
        else:
            user.email_verified = True
            user.email_token = None
            update_db()
            return redirect(url_for('views.login'))
    except:
        abort(404)


@views.route('/otp-setup')
def otp_setup():
    if 'username' not in session:
        return redirect(url_for('views.login'))
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('views.login'))
    return render_template('otp-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@views.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)
    user.otp_secret = pyotp.random_base32()
    update_db_no_close()
    if user.prev_token is not None:
        html = render_template('/email_templates/reset.html', reset="OTP",
                               time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        subject = "HX-Bank - OTP Reset"
        send_email(user.email, subject, html)
        new_message = Message("HX-Bank", f"You have performed a OTP secret reset on "
                                         f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", user.id)
        add_db_no_close(new_message)
    del session['username']
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@views.route('/login', methods=['GET', 'POST'])
def login():
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    logger = logging.getLogger('auth_log')
    if current_user.is_authenticated:
        # Logging.
        logger.info(f"src_ip {ip_source} -> {current_user.username} user account successfully logged in")

        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))
        return redirect(url_for('views.dashboard'))
    form = LoginForm()
    error = "Login Failed"
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if flask_bcrypt.check_password_hash(user.password_hash, form.password.data):
                if user.is_disabled:
                    error = "Account has been locked out. Please contact customer support for assistance."
                    return render_template('login.html', title="Login", form=form, login_error=error)
                session['username'] = user.username
                return redirect(url_for('views.otp_input'))
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts > 3:
                    # Logging.
                    logger.warning(f"src_ip {ip_source} -> {user.username} user account has been locked out")

                    user.is_disabled = True
                update_db()

                # Logging.
                logger.warning(f"src_ip {ip_source} -> {user.username} user account failed to login")

                return render_template('login.html', title="Login", form=form, login_error=error)
        else:
            return render_template('login.html', title="Login", form=form, login_error=error)
    return render_template('login.html', title="Login", form=form)


@views.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Logging.
    logger = logging.getLogger('auth_log')
    logger.info(f"src_ip {ip_source} -> {current_user.username} user account successfully logged out")

    logout_user()
    session.clear()
    return redirect(url_for('views.login'))


@views.route('/otp-input', methods=['GET', 'POST'])
def otp_input():
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    if 'username' not in session:
        return redirect(url_for('views.login'))
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))
        return redirect(url_for('views.dashboard'))
    form = Token2FAForm(request.form)
    error = "Invalid Token"
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=session['username']).first()
        if user and user.prev_token == form.token.data:
            error = "Something went wrong"
            return render_template('otp-input.html', form=form, login_error=error)
        elif user and user.verify_totp(form.token.data):
            del session['username']
            login_user(user)
            if current_user.failed_login_attempts > 0:
                new_message = Message("HX-Bank", f"There were {current_user.failed_login_attempts} failed login "
                                                 f"attempt(s) between your current and last session", current_user.id)
                add_db_no_close(new_message)
            user.last_login = datetime.now()
            user.failed_login_attempts = 0
            user.prev_token = form.token.data
            update_db_no_close()
            new_message = Message("HX-Bank", f"You have logged in on "
                                             f"{current_user.last_login.strftime('%Y-%m-%d %H:%M:%S')}",
                                  current_user.id)

            # Logging.
            log_message = f"src_ip {ip_source} -> {current_user.username} logged in on {current_user.last_login.strftime('%Y-%m-%d %H:%M:%S')}"
            logger = logging.getLogger('auth_log')
            logger.info(log_message)
            add_db_no_close(new_message)
            if current_user.is_admin:
                return redirect(url_for('views.admin_dashboard'))
            if current_user.email_verified is False:
                return redirect(url_for('views.unverified_email'))
            else:
                return redirect(url_for('views.dashboard'))
        else:
            return render_template('otp-input.html', form=form, login_error=error)
    return render_template('otp-input.html', form=form)


@views.route('/unverified-email', methods=['GET'])
@login_required
def unverified_email():
    if current_user.email_verified:
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))
        else:
            return redirect(url_for('views.dashboard'))
    return render_template('verify-email.html')


@views.route('/resend-verification', methods=['GET'])
@login_required
def resend_verification():
    if current_user.email_verified:
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))
        else:
            return redirect(url_for('views.dashboard'))
    token = generate_token(current_user.email)
    confirm_url = url_for('views.confirm_email', token=token, _external=True)
    html = render_template('/email_templates/activate.html', confirm_url=confirm_url)
    subject = "HX-Bank - Email Verification"
    send_email(current_user.email, subject, html)
    return redirect(url_for('views.unverified_email'))


@views.route('/reset-identify', methods=['GET', 'POST'])
def reset_identify():
    selected = request.args.get('type')
    if selected == "pwd":
        session['type'] = "pwd"
    elif selected == "username":
        session['type'] = "username"
    elif selected == "otp":
        session['type'] = "otp"
    else:
        if selected is None:
            if 'type' not in session:
                return redirect(url_for('views.login'))
    form = ResetFormIdentify(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        error = "Identification Failed"
        user = User.query.filter_by(nric=form.nric.data.upper()).first()
        if user:
            session['nric'] = user.nric
            session['dob'] = user.dob
            if "username" in session and session['type'] == "otp":
                session['email'] = user.email
                user_username = User.query.filter_by(username=session['username']).first()
                if user_username.nric == session['nric'] and user_username.dob == session['dob'] \
                        and user_username.email == session['email']:
                    del session['nric']
                    del session['dob']
                    return redirect(url_for("views.reset_email_auth"))
                else:
                    return redirect(url_for("views.login"))
            else:
                if form.dob.data == session['dob']:
                    del session['dob']
                    return redirect(url_for("views.reset_authenticate"))
                else:
                    return render_template('reset-identify.html', form=form, identity_error=error)
        else:
            return render_template('reset-identify.html', form=form, identity_error=error)
    return render_template('reset-identify.html', form=form)


@views.route('/reset-email-auth', methods=['GET', 'POST'])
def reset_email_auth():
    email = session['email']
    del session['email']
    token = generate_token(email)
    user = User.query.filter_by(username=session['username']).first()
    user.email_token = token
    update_db()
    confirm_url = url_for('views.confirm_otp', token=token, _external=True)
    html = render_template('/email_templates/otp.html', confirm_url=confirm_url,
                           time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    subject = "HX-Bank - OTP Reset"
    send_email(email, subject, html)
    return redirect(url_for('views.login'))


@views.route('/confirm_otp/<token>')
def confirm_otp(token):
    try:
        email = confirm_token(token)
        user = User.query.filter_by(email=email).first()
        if user.email_token != token:
            abort(404)
        else:
            user.email_token = None
            update_db()
            return redirect(url_for('views.otp_setup'))
    except:
        abort(404)


@views.route('/reset-authenticate', methods=['GET', 'POST'])
def reset_authenticate():
    if 'nric' not in session:
        return redirect(url_for('views.reset_identify'))
    if 'type' not in session:
        return redirect(url_for("views.login"))
    form = ResetFormAuthenticate(request.form)
    error = "Invalid Token"
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(nric=session['nric']).first()
        if user and user.prev_token == form.token.data:
            error = "Something went wrong"
            return render_template('otp-input.html', form=form, authenticate_error=error)
        elif user and user.verify_totp(form.token.data):
            if session['type'] == "pwd":
                del session['type']
                return redirect(url_for("views.reset_pwd"))
            elif session['type'] == "username":
                del session['type']
                return redirect(url_for("views.reset_username"))
            else:
                return redirect(url_for('views.login'))
        else:
            return render_template('reset-authenticate.html', form=form, authenticate_error=error)
    return render_template('reset-authenticate.html', form=form)


@views.route('/reset-pwd', methods=['GET', 'POST'])
def reset_pwd():
    if 'nric' not in session:
        return redirect(url_for('views.reset_identify'))
    form = ResetPasswordForm(request.form)
    error = "Reset Failed"
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(nric=session['nric']).first()
        if user:
            del session['nric']
            password = flask_bcrypt.generate_password_hash(form.password.data)
            user.password_hash = password
            update_db_no_close()
            html = render_template('/email_templates/reset.html', reset="password",
                                   time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            subject = "HX-Bank - Password Reset"
            send_email(user.email, subject, html)
            new_message = Message("HX-Bank", f"You have performed a password reset on "
                                             f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", user.id)
            add_db(new_message)
            return redirect(url_for("views.login"))
        else:
            return render_template('change-pwd.html', form=form, reset_error=error)
    return render_template('change-pwd.html', form=form)


@views.route('/reset-username', methods=['GET', 'POST'])
def reset_username():
    if 'nric' not in session:
        return redirect(url_for('views.reset_identify'))
    form = ResetUsernameForm(request.form)
    error = "Reset Failed"
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(nric=session['nric']).first()
        if user:
            username = User.query.filter_by(username=form.username.data).first()
            if username:
                return render_template('reset-username.html', form=form, reset_error="Username exists")
            else:
                del session['nric']
                user.username = form.username.data
                update_db_no_close()
                html = render_template('/email_templates/reset.html', reset="username",
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                subject = "HX-Bank - Username Reset"
                send_email(user.email, subject, html)
                new_message = Message("HX-Bank", f"You have performed a username change on "
                                                 f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", user.id)
                add_db(new_message)
            return redirect(url_for("views.login"))
        else:
            return render_template('reset-username.html', form=form, reset_error=error)
    return render_template('reset-username.html', form=form)


@views.route('/personal-banking/dashboard', methods=['GET'])
@login_required
# @check_email_verification
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))
    user_data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    user_acc_number = Account.query.filter_by(userid=current_user.id).first().acc_number
    transfer_data = Transaction.query.filter_by(transferrer_acc_number=user_acc_number).all()
    transferee_data = Transaction.query.filter_by(transferee_acc_number=user_acc_number).all()
    data = []
    for item in list(reversed(transfer_data))[:5]:
        data.append({"date_transferred": item.date_transferred.strftime('%Y-%m-%d %H:%M:%S'),
                     "amt_transferred": Decimal(item.amt_transferred).quantize(TWO_PLACES),
                     "transferrer_acc": item.transferrer_acc_number, "transferee_acc": item.transferee_acc_number,
                     "description": item.description, "require_approval": item.require_approval,
                     "status": item.status, "debit": False})
    for item in list(reversed(transferee_data))[:5]:
        if item.transferrer_acc_number != item.transferee_acc_number:
            data.append({"date_transferred": item.date_transferred.strftime('%Y-%m-%d %H:%M:%S'),
                         "amt_transferred": Decimal(item.amt_transferred).quantize(TWO_PLACES),
                         "transferrer_acc": item.transferrer_acc_number, "transferee_acc": item.transferee_acc_number,
                         "description": item.description, "require_approval": item.require_approval,
                         "status": item.status, "debit": True})
    data = {x['date_transferred']: x for x in data}.values()
    msg_data = load_nav_messages()
    return render_template('dashboard.html', title="Dashboard", data=user_data, msg_data=msg_data, recent_trans=data)


@views.route("/admin/admin-dashboard", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('views.dashboard'))
    data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    msg_data = load_nav_messages()
    if not current_user.is_admin:
        return render_template('dashboard.html', title="Dashboard", data=data, msg_data=msg_data)
    return render_template('/admin/admin-dashboard.html', title="Admin Dashboard", data=data, msg_data=msg_data)


@views.route("/personal-banking/transfer", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def transfer():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))
    msg_data = load_nav_messages()
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Init the TransferMoneyForm
    form = TransferMoneyForm()

    # Dynamically populate the TransferMoneyForm.
    transferee_data = Transferee.query.filter_by(transferer_id=current_user.id).all()
    data = []
    for transferee in transferee_data:
        transferee_acc_data = Account.query.filter_by(userid=transferee.transferee_id).first()
        acc_num = transferee_acc_data.acc_number
        transferee_user_data = User.query.filter_by(id=transferee.transferee_id).first()
        first_name = transferee_user_data.firstname
        last_name = transferee_user_data.lastname
        user_data = f"{acc_num} - {first_name} {last_name}"
        data.append(user_data)
    form.transferee_acc.choices = data

    # Get the transferrer's account information.
    transferrer_userid = current_user.id
    transferrer_acc = Account.query.filter_by(userid=transferrer_userid).first()

    # Check if the form was submitted.
    if request.method == 'POST' and form.validate_on_submit():
        # Transaction description.
        description = form.description.data

        # Amount to debit and credit from transferee and transferrer respectively.
        amount = float(Decimal(form.amount.data).quantize(TWO_PLACES))
        if amount < 0.1:
            error = "Invalid amount (Minimum $0.10)"
            return render_template('transfer.html', title="Transfer", form=form, msg_data=msg_data, xfer_error=error)

        # Get the transferee's account information.
        transferee_acc_number = form.transferee_acc.data.split(" ")[0]
        transferee_userid = Account.query.filter_by(acc_number=transferee_acc_number).first().userid

        # Check that the amount to be transferred does not exceed the transfer limit.
        day_amount = Decimal(transferrer_acc.acc_xfer_daily + amount).quantize(TWO_PLACES)

        if datetime.now().date() < transferrer_acc.reset_xfer_limit_date.date() and day_amount > transferrer_acc.acc_xfer_limit:
            error = "Amount to be transferred exceeds daily transfer limit"
            return render_template('transfer.html', title="Transfer", form=form, xfer_error=error, msg_data=msg_data,
                                   balance=transferrer_acc.acc_balance)
        if transferrer_acc.acc_balance - transferrer_acc.money_on_hold < amount:
            error = "Insufficient funds"
            return render_template('transfer.html', title="Transfer", form=form, xfer_error=error, msg_data=msg_data,
                                   balance=transferrer_acc.acc_balance)

        # Create a transaction.
        transferer_acc_number = Account.query.filter_by(userid=transferrer_userid).first().acc_number
        require_approval = False
        status = 0

        if amount >= 10000:
            require_approval = True
            status = 1

        new_transaction = Transaction(Decimal(amount).quantize(TWO_PLACES), transferer_acc_number,
                                      transferee_acc_number, description, require_approval, status)
        add_db_no_close(new_transaction)

        # Get the transferrer and transferee accounts. 
        transferrer_acc = Account.query.filter_by(userid=transferrer_userid).first()
        transferee_acc = Account.query.filter_by(userid=transferee_userid).first()

        # Add money to onhold if approval is required. 
        if require_approval:
            money_on_hold = Decimal(transferrer_acc.money_on_hold + amount).quantize(TWO_PLACES)
            transferrer_acc.money_on_hold = money_on_hold

        else:
            # Update the balance for both transferrer and transferee.
            transferrer_acc_balance = Decimal(transferrer_acc.acc_balance - amount).quantize(TWO_PLACES)
            transferrer_acc.acc_balance = transferrer_acc_balance
            transferee_acc_balance = Decimal(transferee_acc.acc_balance - amount).quantize(TWO_PLACES)
            transferee_acc.acc_balance = transferee_acc_balance
            if datetime.now().date() > transferee_acc.reset_xfer_limit_date.date():
                transferee_acc.reset_xfer_limit = date.today() + timedelta(days=1)
                transferrer_acc.acc_xfer_daily = 0
            transferrer_acc_xfer_daily = Decimal(transferrer_acc.acc_xfer_daily + amount).quantize(TWO_PLACES)
            transferrer_acc.acc_xfer_daily = transferrer_acc_xfer_daily

        update_db_no_close()

        # Logging.
        logger = logging.getLogger('user_activity_log')
        logger.info(f"src_ip {ip_source} -> {Decimal(amount).quantize(TWO_PLACES)} transferred from {transferer_acc_number} to {transferee_acc_number}")

        # Return approval required page.
        if require_approval:
            html = render_template('/email_templates/transfer-pending.html',
                                   amount=Decimal(amount).quantize(TWO_PLACES),
                                   acc_num=transferee_acc.acc_number, time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            subject = "HX-Bank - Add Recipient"
            send_email(current_user.email, subject, html)
            new_message = Message("HX-Bank",
                                  f"Your requested transfer of "
                                  f"${Decimal(amount).quantize(TWO_PLACES)} to "
                                  f"{form.transferee_acc.data} is currently pending for approval.", transferrer_userid)
            add_db(new_message)
            return redirect(url_for('views.approval_required'))

        # Return success page.
        html = render_template('/email_templates/transfer-success.html',
                               amount=Decimal(amount).quantize(TWO_PLACES),
                               acc_num=transferee_acc.acc_number, time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        subject = "HX-Bank - Add Recipient"
        send_email(current_user.email, subject, html)
        new_message = Message("HX-Bank", f"Your have requested transfer of ${Decimal(amount).quantize(TWO_PLACES)}"
                                         f" to {form.transferee_acc.data} is successful.", transferrer_userid)
        add_db(new_message)
        return redirect(url_for('views.success'))

    # Render the HTML template.
    return render_template('transfer.html', title="Transfer", form=form, msg_data=msg_data,
                           balance=Decimal(transferrer_acc.acc_balance).quantize(TWO_PLACES))


@views.route("/personal-banking/transfer-onetime", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def transfer_onetime():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))
    msg_data = load_nav_messages()
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Init the TransferMoneyForm
    form = TransferMoneyOneTimeForm()

    # Get the transferrer's account information.
    transferrer_userid = current_user.id
    transferrer_acc = Account.query.filter_by(userid=transferrer_userid).first()

    # Check if the form was submitted.
    if request.method == 'POST' and form.validate_on_submit():
        # Transaction description.
        description = form.description.data

        # Amount to debit and credit from transferee and transferrer respectively.
        amount = float(Decimal(form.amount.data).quantize(TWO_PLACES))
        if amount < 0.1:
            error = "Invalid amount (Minimum $0.10)"
            return render_template('transfer.html', title="Transfer", form=form, msg_data=msg_data, xfer_error=error)

        # Get the transferee's account information.
        transferee_acc_number = form.transferee_acc.data.split(" ")[0]
        transferee_acc = Account.query.filter_by(acc_number=transferee_acc_number).first()

        # Return error if transferee does not exist.  
        if transferee_acc is None:
            error = "Transferee does not exist"
            return render_template('transfer-onetime.html', title="Transfer (onetime)", form=form, msg_data=msg_data,
                                   balance=Decimal(transferrer_acc.acc_balance).quantize(TWO_PLACES),
                                   transferee_error=error)

        transferee_userid = Account.query.filter_by(acc_number=transferee_acc_number).first().userid

        # Check that the amount to be transferred does not exceed the transfer limit.
        day_amount = Decimal(transferrer_acc.acc_xfer_daily + amount).quantize(TWO_PLACES)

        if datetime.now().date() < transferrer_acc.reset_xfer_limit_date.date() and day_amount > transferrer_acc.acc_xfer_limit:
            error = "Amount to be transferred exceeds daily transfer limit"
            return render_template('transfer.html', title="Transfer", form=form, xfer_error=error, msg_data=msg_data,
                                   balance=Decimal(transferrer_acc.acc_balance).quantize(TWO_PLACES))
        if transferrer_acc.acc_balance < amount:
            error = "Insufficient funds"
            return render_template('transfer.html', title="Transfer", form=form, xfer_error=error, msg_data=msg_data,
                                   balance=Decimal(transferrer_acc.acc_balance).quantize(TWO_PLACES))

        # Create a transaction.
        transferer_acc_number = Account.query.filter_by(userid=transferrer_userid).first().acc_number
        require_approval = False
        status = 0

        if amount >= 10000:
            require_approval = True
            status = 1

        new_transaction = Transaction(Decimal(amount).quantize(TWO_PLACES), transferer_acc_number,
                                      transferee_acc_number, description, require_approval, status)
        add_db_no_close(new_transaction)

        # Logging.
        logger = logging.getLogger('user_activity_log')
        logger.info(f"src_ip {ip_source} -> {Decimal(amount).quantize(TWO_PLACES)} transferred from {transferer_acc_number} to {transferee_acc_number}")

        # Update the balance for both transferrer and transferee.
        transferrer_acc = Account.query.filter_by(userid=transferrer_userid).first()
        transferee_acc = Account.query.filter_by(userid=transferee_userid).first()
        if require_approval:
            money_on_hold = Decimal(transferrer_acc.money_on_hold + amount).quantize(TWO_PLACES)
            transferrer_acc.money_on_hold = money_on_hold
        else:
            transferrer_acc_balance = Decimal(transferrer_acc.acc_balance - amount).quantize(TWO_PLACES)
            transferrer_acc.acc_balance = transferrer_acc_balance
            transferee_acc_balance = Decimal(transferee_acc.acc_balance - amount).quantize(TWO_PLACES)
            transferee_acc.acc_balance = transferee_acc_balance
            if datetime.now().date() > transferee_acc.reset_xfer_limit_date.date():
                transferee_acc.reset_xfer_limit = date.today() + timedelta(days=1)
                transferrer_acc.acc_xfer_daily = 0
            transferrer_acc_xfer_daily = Decimal(transferrer_acc.acc_xfer_daily + amount).quantize(TWO_PLACES)
            transferrer_acc.acc_xfer_daily = transferrer_acc_xfer_daily

        update_db_no_close()

        # Return approval required page.
        if require_approval:
            html = render_template('/email_templates/transfer-pending.html',
                                   amount=Decimal(amount).quantize(TWO_PLACES),
                                   acc_num=transferee_acc.acc_number, time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            subject = "HX-Bank - Add Recipient"
            send_email(current_user.email, subject, html)
            new_message = Message("HX-Bank",
                                  f"Your requested transfer of $"
                                  f"{Decimal(amount).quantize(TWO_PLACES)} to {form.transferee_acc.data} "
                                  f"is currently pending for approval.", transferrer_userid)
            add_db(new_message)
            return redirect(url_for('views.approval_required'))

        # Return success page.
        html = render_template('/email_templates/transfer-success.html',
                               amount=Decimal(amount).quantize(TWO_PLACES),
                               acc_num=transferee_acc.acc_number, time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        subject = "HX-Bank - Add Recipient"
        send_email(current_user.email, subject, html)
        new_message = Message("HX-Bank", f"Your have requested transfer of ${Decimal(amount).quantize(TWO_PLACES)}"
                                         f" to {form.transferee_acc.data} is successful.", transferrer_userid)
        add_db(new_message)
        return redirect(url_for('views.success'))

    # Render the HTML template.
    return render_template('transfer-onetime.html', title="Transfer (One-Time)", form=form, msg_data=msg_data,
                           balance=transferrer_acc.acc_balance)


@views.route("/personal-banking/add-transferee", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def add_transferee():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))
    msg_data = load_nav_messages()
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    form = AddTransfereeForm()
    if request.method == 'POST' and form.validate_on_submit():
        # Get the transferee info based on the account number provided by the user.
        transferee_acc = Account.query.filter_by(acc_number=form.transferee_acc.data).first()

        # Check that the transferee info does not exist already in the current user's transferee list.
        if transferee_acc:
            validate_if_exist = Transferee.query.filter_by(transferer_id=current_user.id,
                                                           transferee_id=transferee_acc.userid).first()

            # Return error if it exists.
            if validate_if_exist:
                add_error = "Transferee already exists!"
                return render_template('add-transferee.html', title="Add Transferee", form=form, add_error=add_error,
                                       msg_data=msg_data)

            # Add to DB if it does not exist.
            else:
                new_message = Message("HX-Bank", f"You have added account number: {transferee_acc.acc_number}, as a "
                                                 f"transfer recipient", current_user.id)
                add_db_no_close(new_message)
                html = render_template('/email_templates/recipient.html', recipient=transferee_acc.acc_number,
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                subject = "HX-Bank - Add Recipient"
                send_email(current_user.email, subject, html)
                new_transferee = Transferee(current_user.id, transferee_acc.userid)
            
                # Logging.
                logger = logging.getLogger('user_activity_log')
                logger.info(f"src_ip {ip_source} -> {current_user.username} has added {transferee_acc.acc_number} as a transferee")

                add_db(new_transferee)
                return redirect(url_for('views.success'))

        # Return error if the transferee info does not exist based on the account number provided by the user.
        else:
            add_error = "Invalid account!"
            return render_template('add-transferee.html', title="Add Transferee", form=form, add_error=add_error,
                                   msg_data=msg_data)

    return render_template('add-transferee.html', title="Add Transferee", form=form, msg_data=msg_data)


@views.route("/personal-banking/transaction-history", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def transaction_history():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))
    msg_data = load_nav_messages()
    # Get the list of transactions that the user is involved in.
    user_acc_number = Account.query.filter_by(userid=current_user.id).first().acc_number
    transfer_data = Transaction.query.filter_by(transferrer_acc_number=user_acc_number).all()
    transferee_data = Transaction.query.filter_by(transferee_acc_number=user_acc_number).all()
    data = []

    # Combine the transactions together.
    for item in reversed(transfer_data):
        data.append({"date_transferred": item.date_transferred.strftime('%Y-%m-%d %H:%M:%S'),
                     "amt_transferred": Decimal(item.amt_transferred).quantize(TWO_PLACES),
                     "transferrer_acc": item.transferrer_acc_number, "transferee_acc": item.transferee_acc_number,
                     "description": item.description, "require_approval": item.require_approval, "status": item.status,
                     "debit": False})
    for item in reversed(transferee_data):
        if item.transferrer_acc_number != item.transferee_acc_number:
            data.append({"date_transferred": item.date_transferred.strftime('%Y-%m-%d %H:%M:%S'),
                         "amt_transferred": Decimal(item.amt_transferred).quantize(TWO_PLACES),
                         "transferrer_acc": item.transferrer_acc_number, "transferee_acc": item.transferee_acc_number,
                         "description": item.description, "require_approval": item.require_approval,
                         "status": item.status, "debit": True})

    # Sort by latest date first.
    data = {x['date_transferred']: x for x in data}.values()

    # Render template.
    return render_template('transaction-history.html', title="Transaction History", data=data, msg_data=msg_data)


@views.route("/personal-banking/view-transferee", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def view_transferee():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))
    msg_data = load_nav_messages()
    # Init the RemoveTransferForm.
    form = RemoveTransfereeForm()

    #
    transferee_data = Transferee.query.filter_by(transferer_id=current_user.id).all()
    data = []
    form_data_list = []
    for transferee in transferee_data:
        transferee_acc_data = Account.query.filter_by(userid=transferee.transferee_id).first()
        acc_num = transferee_acc_data.acc_number
        transferee_user_data = User.query.filter_by(id=transferee.transferee_id).first()
        first_name = transferee_user_data.firstname
        last_name = transferee_user_data.lastname
        user_data = {"acc_num": acc_num, "first_name": first_name, "last_name": last_name}
        form_data = f"{acc_num} - {first_name} {last_name}"
        data.append(user_data)
        form_data_list.append(form_data)
    form.transferee_acc.choices = form_data_list

    # Check if the remove transferee form was submitted.
    if request.method == "POST" and form.validate_on_submit():
        transferee_acc = form.transferee_acc.data.split(" ")[0]
        transferee_id = Account.query.filter_by(acc_number=transferee_acc).first().userid
        del_transferee = Transferee.query.filter_by(transferer_id=current_user.id, transferee_id=transferee_id).delete()
        update_db()
        return redirect(url_for('views.success'))
    return render_template('view-transferee.html', title="View Transferee", data=data, form=form, msg_data=msg_data)


@views.route("/personal-banking/set-transfer-limit", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def set_transfer_limit():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))
    msg_data = load_nav_messages()
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Init the SetTransferLimitForm.
    form = SetTransferLimitForm()
    if request.method == 'POST' and form.validate_on_submit():
        amount = float(Decimal(form.transfer_limit.data).quantize(TWO_PLACES))
        if amount < 0.1:
            error = "Invalid value"
            return render_template('set-transfer-limit.html', title="Set Transfer Limit", form=form, msg_data=msg_data,
                                   limit_error=error)
        acc = Account.query.filter_by(userid=current_user.id).first()
        new_message = Message("HX-Bank", f"Your new transfer limit is ${Decimal(amount).quantize(TWO_PLACES)}",
                              current_user.id)
        add_db_no_close(new_message)
        html = render_template('/email_templates/transfer-limit.html', amount=Decimal(amount).quantize(TWO_PLACES),
                               time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        subject = "HX-Bank - New Transfer Limit"
        send_email(current_user.email, subject, html)

        # Logging.
        logger = logging.getLogger('user_activity_log')
        logger.info(f"src_ip {ip_source} -> {current_user.username} has updated transfer limit to ${amount}")

        acc.acc_xfer_limit = Decimal(amount).quantize(TWO_PLACES)
        update_db()

        return redirect(url_for('views.success'))
    return render_template('set-transfer-limit.html', title="Set Transfer Limit", form=form, msg_data=msg_data)


@views.route("/personal-banking/topup-balance", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def topup_balance():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))
    msg_data = load_nav_messages()
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    form = TopUpForm()
    if request.method == 'POST' and form.validate_on_submit():
        user_acc = db.session.query(Account).join(User).filter(User.id == current_user.id).first().acc_number
        amount = float(Decimal(form.amount.data).quantize(TWO_PLACES))
        if amount < 1:
            error = "Invalid amount (Minimum $1)"
            return render_template('topup.html', title="Top Up", form=form, msg_data=msg_data, topup_error=error)
        acc = Account.query.filter_by(userid=current_user.id).first()
        acc_balance = Decimal(acc.acc_balance + amount).quantize(TWO_PLACES)
        acc.acc_balance = acc_balance
        new_message = Message("HX-Bank", f"You have made a request to top up $"
                                         f"{Decimal(amount).quantize(TWO_PLACES)}", current_user.id)
        add_db_no_close(new_message)
        html = render_template('/email_templates/top-up.html', amount=Decimal(amount).quantize(TWO_PLACES),
                               time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        subject = "HX-Bank - Top Up"
        send_email(current_user.email, subject, html)

        # Logging.
        logger = logging.getLogger('user_activity_log')
        logger.info(f"src_ip {ip_source} -> {current_user.username} has topped up {amount}")

        update_db()
        description = f"Self-service top up of ${Decimal(amount).quantize(TWO_PLACES)}"

        # Create transaction
        new_transaction = Transaction(form.amount.data, user_acc, user_acc, description, False, 0)
        add_db(new_transaction)

        return redirect(url_for('views.success'))
    return render_template('topup.html', title="Top Up", form=form, msg_data=msg_data)


@views.route("/communication/compose", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def compose():
    msg_data = load_nav_messages()
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    form = ComposeMessage()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.recipient.data).first()
        if user:
            error = "Message Sent!"
            new_message = Message(current_user.username, form.message.data, user.id)
            
            # Logging.
            logger = logging.getLogger('user_activity_log')
            logger.info(f"src_ip {ip_source} -> {current_user.username} has sent a message to {user.username}")

            add_db_no_close(new_message)
            return render_template('compose.html', msg_data=msg_data, form=form, compose_error=error)
        else:
            error = "User does not exist"
            return render_template('compose.html', msg_data=msg_data, form=form, compose_error=error)
    return render_template('compose.html', msg_data=msg_data, form=form)


@views.route("/communication/message-center", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def message_center():
    msg_data = load_nav_messages()
    form = SecureMessageForm()
    if request.method == 'POST' and form.validate_on_submit():
        msg = db.session.query(Message).filter_by(id=form.msg.data).first()
        if msg:
            check = db.session.query(Message).join(User).filter(msg.userid == current_user.id).first()
        else:
            error = "Something went wrong"
            return render_template('message-center.html', title="Secure Message Center", msg_data=msg_data, form=form,
                                   msg_error=error)
        if check:
            if form.data["mark"]:
                msg.read = True
                update_db()
            elif form.data["unmark"]:
                msg.read = False
                update_db()
            elif form.data["delete"]:
                del_db(msg)
        else:
            error = "Something went wrong"
            return render_template('message-center.html', title="Secure Message Center", msg_data=msg_data, form=form,
                                   msg_error=error)
        return redirect(url_for('views.message_center'))
    return render_template('message-center.html', title="Secure Message Center", msg_data=msg_data, form=form)


@views.route("/admin/transaction-management", methods=["GET", "POST"])
@login_required
# @check_email_verification
def transaction_management():
    if not current_user.is_admin:
        return redirect(url_for('views.dashboard'))
    form = ApproveTransactionForm()

    # Check that the form was submitted.
    if request.method == "POST" and form.validate_on_submit():
        # Get the transaction id. 
        transaction = Transaction.query.filter_by(id=form.transactionid.data).first()

        # Get the transferrer's account information.
        transferrer_acc = Account.query.filter_by(acc_number=transaction.transferrer_acc_number).first()

        # Update the balance for both transferrer and transferee if approved. 
        if form.approve.data:
            transferee_acc = Account.query.filter_by(acc_number=transaction.transferee_acc_number).first()
            transferee_acc.acc_balance += transferrer_acc.money_on_hold
            transferrer_acc.acc_balance -= transferrer_acc.money_on_hold
            transferrer_acc.money_on_hold -= transferrer_acc.money_on_hold
            transaction.status = 0
            transaction.require_approval = False
            update_db_no_close()

        # Update the balance for the transferrer.
        else:
            transferrer_acc.acc_balance += transferrer_acc.money_on_hold
            transferrer_acc.money_on_hold -= transferrer_acc.money_on_hold
            transaction.status = 2
            transaction.require_approval = False
            update_db_no_close()
    transactions = Transaction.query.filter_by(require_approval=True).all()
    data = []
    for item in transactions:
        data.append(item)
    msg_data = load_nav_messages()
    return render_template("/admin/transaction-management.html", data=data, form=form, msg_data=msg_data)


@views.route("/admin/user_management", methods=["GET", "POST"])
@login_required
# @check_email_verification
def user_management():
    if not current_user.is_admin:
        return redirect(url_for('views.dashboard'))
    form = UnlockUserForm()
    if request.method == "POST" and form.validate_on_submit():
        user_acc = User.query.filter_by(id=form.userid.data).first()
        user_acc.is_disabled = False
        update_db()
        return redirect(url_for('views.user_management'))
    locked_acc = User.query.filter_by(is_disabled=True).all()
    data = []
    for user in locked_acc:
        data.append({"userid": user.id, "username": user.username, "date_joined": user.date_joined,
                     "failed_login_attempts": user.failed_login_attempts, "last_login": user.last_login})
    msg_data = load_nav_messages()
    return render_template("/admin/user-management.html", data=data, form=form, msg_data=msg_data)


@views.route("/account_management/account-settings", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def acc_settings():
    data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    msg_data = load_nav_messages()
    if current_user.is_admin:
        return render_template('account-settings.html', title="Admin settings", data=data, msg_data=msg_data)
    return render_template('account-settings.html', title="User settings", data=data, msg_data=msg_data)


@views.route('/account-management/change-pwd', methods=['GET', 'POST'])
@login_required
# @check_email_verification
def change_pwd():
    msg_data = load_nav_messages()
    form = ChangePasswordForm()
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=current_user.username).first()
        if user:
            if user.prev_token == form.token.data:
                error = "Something went wrong"
                return render_template('change-pwd.html', form=form, reset_error=error, msg_data=msg_data)
            if flask_bcrypt.check_password_hash(user.password_hash, form.current_password.data) and user.verify_totp(
                    form.token.data):
                password = flask_bcrypt.generate_password_hash(form.password.data)
                user.password_hash = password
                update_db_no_close()
                html = render_template('/email_templates/reset.html', reset="password",
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                subject = "HX-Bank - Change Password"
                send_email(current_user.email, subject, html)

                # Logging.
                logger = logging.getLogger('user_activity_log')
                logger.info(f"src_ip {ip_source} -> {current_user.username} has changed their password")

                new_message = Message("HX-Bank",
                                      f"You have performed a password change on "
                                      f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", user.id)
                add_db(new_message)

                return redirect(url_for("views.acc_settings"))
            else:
                error = "Incorrect OTP"
                return render_template('change-pwd.html', form=form, reset_error=error, msg_data=msg_data)
    return render_template('change-pwd.html', form=form, msg_data=msg_data)


@views.route('/account-management/change-username', methods=['GET', 'POST'])
@login_required
# @check_email_verification
def change_username():
    msg_data = load_nav_messages()
    form = ChangeUsernameForm()
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=current_user.username).first()
        if user:
            if user.prev_token == form.token.data:
                error = "Something went wrong"
                return render_template('change-username.html', form=form, reset_error=error, msg_data=msg_data)
            if user.verify_totp(form.token.data):
                if form.old_username.data == form.new_username.data:
                    error = "Username cannot be the same"
                    return render_template('change-username.html', form=form, reset_error=error, msg_data=msg_data)
                if form.old_username.data == user.username:
                    error = "Something went wrong"
                    return render_template('change-username.html', form=form, reset_error=error, msg_data=msg_data)
                user.username = form.new_username.data
                update_db_no_close()
                html = render_template('/email_templates/reset.html', reset="username",
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                subject = "HX-Bank - Change Username"
                send_email(current_user.email, subject, html)

                # Logging.
                logger = logging.getLogger('user_activity_log')
                logger.info(f"src_ip {ip_source} -> {current_user.username} has updated their username")

                new_message = Message("HX-Bank",
                                      f"You have performed a username change on "
                                      f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", user.id)
                add_db(new_message)
                return redirect(url_for("views.acc_settings"))
            else:
                error = "Incorrect OTP"
                return render_template('change-pwd.html', form=form, reset_error=error, msg_data=msg_data)
    return render_template('change-username.html', form=form, msg_data=msg_data)


@views.route('/account-management/change-otp', methods=['GET', 'POST'])
@login_required
# @check_email_verification
def change_otp():
    msg_data = load_nav_messages()
    form = Token2FAForm()
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    error = "Invalid Token"
    if request.method == 'POST' and form.validate_on_submit():
        if current_user.prev_token == form.token.data:
            error = "Something went wrong"
            return render_template('auth-change-otp.html', form=form, msg_data=msg_data, otp_error=error)
        elif current_user.verify_totp(form.token.data):
            # Logging.
            logger = logging.getLogger('user_activity_log')
            logger.info(f"src_ip {ip_source} -> {current_user.username} has updated their OTP")

            return redirect(url_for("views.auth_otp_reset"))
        else:
            return render_template('auth-change-otp.html', form=form, msg_data=msg_data, otp_error=error)
    return render_template('auth-change-otp.html', form=form, msg_data=msg_data)


@views.route('/account-management/otp-setup', methods=['GET'])
@login_required
# @check_email_verification
def auth_otp_reset():
    msg_data = load_nav_messages()
    return render_template('change-otp.html', msg_data=msg_data), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@views.route('/account-management/qrcode', methods=['GET'])
@login_required
# @check_email_verification
def auth_qrcode():
    current_user.otp_secret = pyotp.random_base32()
    update_db_no_close()
    if current_user.prev_token is not None:
        html = render_template('/email_templates/reset.html', reset="OTP",
                               time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        subject = "HX-Bank - OTP Reset"
        send_email(current_user.email, subject, html)
        new_message = Message("HX-Bank", f"You have performed a OTP secret reset on "
                                         f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", current_user.id)
        add_db_no_close(new_message)
    url = pyqrcode.create(current_user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@views.route("/success")
@login_required
# @check_email_verification
def success():
    return render_template('success.html', title="Success")


@views.route("/approval-required")
@login_required
# @check_email_verification
def approval_required():
    return render_template('approval-required.html', title="Approval Required")


@views.route("/robots.txt", methods=['GET'])
def robots():
    return render_template('robots.txt', title="Robots")


@views.route("/api/acc-overview", methods=['GET'])
@login_required
# @check_email_verification
def acc_overview():
    if current_user.is_admin:
        abort(403)
    data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    if data:
        return jsonify({'acc_balance': Decimal(data.acc_balance).quantize(TWO_PLACES),
                        'acc_balance_on_hold': Decimal(data.money_on_hold).quantize(TWO_PLACES),
                        'acc_xfer_limit': Decimal(data.acc_xfer_limit).quantize(TWO_PLACES),
                        'acc_xfer_daily': Decimal(data.acc_xfer_daily).quantize(TWO_PLACES)}), 200


@views.route("/api/barchart-graph", methods=['GET'])
@login_required
# @check_email_verification
def barchart_graph():
    if current_user.is_admin:
        abort(403)
    current_year = datetime.now().year
    user_acc_number = Account.query.filter_by(userid=current_user.id).first().acc_number
    transfer_data = Transaction.query.filter_by(transferrer_acc_number=user_acc_number).all()
    transferee_data = Transaction.query.filter_by(transferee_acc_number=user_acc_number).all()
    money_in = {x + 1: 0 for x in range(12)}
    money_out = {x + 1: 0 for x in range(12)}
    for item in transfer_data:
        if item.date_transferred.year == current_year:
            if not item.require_approval:
                if item.transferrer_acc_number != item.transferee_acc_number:
                    money_out[item.date_transferred.month] += item.amt_transferred
    for item in transferee_data:
        if item.date_transferred.year == current_year:
            money_in[item.date_transferred.month] += item.amt_transferred
    return jsonify({'money_in': money_in, 'money_out': money_out}), 200


@views.route("/api/recent-transactions", methods=['GET'])
@login_required
# @check_email_verification
def recent_transactions():
    if current_user.is_admin:
        abort(403)
    user_acc_number = Account.query.filter_by(userid=current_user.id).first().acc_number
    transfer_data = Transaction.query.filter_by(transferrer_acc_number=user_acc_number).all()
    transferee_data = Transaction.query.filter_by(transferee_acc_number=user_acc_number).all()
    data = []
    for item in list(reversed(transfer_data))[:5]:
        data.append({"date_transferred": item.date_transferred.strftime('%Y-%m-%d %H:%M:%S'),
                     "amt_transferred": Decimal(item.amt_transferred).quantize(TWO_PLACES),
                     "transferrer_acc": item.transferrer_acc_number, "transferee_acc": item.transferee_acc_number,
                     "description": item.description, "require_approval": item.require_approval,
                     "status": item.status, "debit": False})
    for item in list(reversed(transferee_data))[:5]:
        if item.transferrer_acc_number != item.transferee_acc_number:
            data.append({"date_transferred": item.date_transferred.strftime('%Y-%m-%d %H:%M:%S'),
                         "amt_transferred": Decimal(item.amt_transferred).quantize(TWO_PLACES),
                         "transferrer_acc": item.transferrer_acc_number, "transferee_acc": item.transferee_acc_number,
                         "description": item.description, "require_approval": item.require_approval,
                         "status": item.status, "debit": True})
    data.sort(key=lambda r: r["date_transferred"], reverse=False)
    temp = {}
    trans_no = 0
    for item in data:
        placeholder_temp = str(trans_no)
        temp[placeholder_temp] = item
        trans_no += 1
    return jsonify(temp), 200


@views.route("/personal-banking/profile", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def profile():
    user_data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    user_acc_number = Account.query.filter_by(userid=current_user.id).first().acc_number
    msg_data = load_nav_messages()
    return render_template('profile.html', title="Profile Page", data=user_data, msg_data=msg_data)


@views.before_request
def make_session_permanent():
    session.permanent = True


@views.after_request
def add_header(r):
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['X-Frame-Options'] = 'SAMEORIGIN'
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['X-XSS-Protection'] = '1; mode=block'
    # r.headers['Content-Security-Policy'] = "default-src 'self'"
    # r.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return r
