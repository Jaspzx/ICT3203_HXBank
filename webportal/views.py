import pyqrcode
import logging
import ipaddress
from decimal import Decimal
from io import BytesIO
from .utils.interact_db import *
from flask import Blueprint, redirect, url_for, render_template, request, session, abort, jsonify, escape
from flask_login import login_required, login_user, logout_user
from webportal import flask_bcrypt, login_manager, encryptor
from webportal.models.Transferee import *
from .forms import *
from .utils.messaging import *
from functools import wraps
from webportal.controllers.MessageManagementController import MessageManagementController
from webportal.controllers.AccountManagementController import AccountManagementController
from webportal.controllers.EmailManagementController import EmailManagementController
from webportal.controllers.BankAccountManagementController import BankAccountManagementController

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
def load_user(session_token):
    return User.query.filter_by(session_token=session_token).first()


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
        mmc = MessageManagementController()
        emc = EmailManagementController()
        amc = AccountManagementController()
        bamc = BankAccountManagementController()

        username = escape(form.username.data)
        firstname = escape(form.firstname.data)
        lastname = escape(form.lastname.data)
        address = escape(form.address.data)
        email = escape(form.email.data)
        mobile = escape(form.mobile.data)
        nric = escape(form.nric.data.upper())
        dob = form.dob.data
        age = date.today().year - dob.year
        password = flask_bcrypt.generate_password_hash(form.password.data)

        check, register_error = amc.verify_details(username, email, mobile, nric, dob, age)
        if check:
            return render_template('register.html', title="Register", form=form, register_error=register_error)

        logger = logging.getLogger('user_activity_log')

        amc.add_user(username, firstname, lastname, address, email, mobile, nric, dob, password, None, None, 0)

        logger.info(f"src_ip {ip_source} -> {username} user account created")

        user = User.query.filter_by(username=username).first()

        acc_number, welcome_amt = bamc.add_bank_account(user.id)

        mmc.send_welcome_msg(welcome_amt, user)

        logger.info(f"src_ip {ip_source} -> Bank acc {acc_number} created and linked to {username}")

        session['username'] = username
        token = emc.generate_token(username, user)
        confirm_url = url_for('views.confirm_email', token=token, _external=True)
        emc.send_email(email, "HX-Bank - Email Verification",
                       render_template('/email_templates/activate.html', confirm_url=confirm_url))

        return redirect(url_for("views.otp_setup"))
    return render_template('register.html', title="Register", form=form)


@views.route('/confirm/<token>')
def confirm_email(token):
    emc = EmailManagementController()

    try:
        email = emc.confirm_token(token)
        if emc.verify_token(email, token):
            if 'username' in session:
                pass

            return redirect(url_for('views.login'))
        else:
            abort(404)
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
    mmc = MessageManagementController()
    emc = EmailManagementController()
    amc = AccountManagementController()

    if 'username' not in session:
        abort(404)

    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))

    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    if user.prev_token is not None:
        if 'flag' not in session:
            session.clear()
            return redirect(url_for("views.login"))
        del session['flag']
        emc.send_email(user.email, "HX-Bank - OTP Reset",
                       render_template('/email_templates/reset.html', reset="OTP",
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        mmc.send_otp_reset(user)

    amc.generate_pyotp(user)
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
    amc = AccountManagementController()

    ip_source = ipaddress.IPv4Address(request.remote_addr)

    logger = logging.getLogger('auth_log')
    if current_user.is_authenticated:
        logger.info(f"src_ip {ip_source} -> {current_user.username} user account successfully logged in")

        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))

        return redirect(url_for('views.dashboard'))

    form = LoginForm()
    error = "Login Failed"

    if request.method == 'POST' and form.validate_on_submit():

        user = User.query.filter_by(username=escape(form.username.data)).first()
        password = form.password.data

        if user:
            auth = amc.authenticate(user, password)

            if auth == 1:
                session['username'] = user.username
                return redirect(url_for('views.otp_input'))

            elif auth == 2:
                error = "Account has been locked out. Please contact customer support for assistance."
                return render_template('login.html', title="Login", form=form, login_error=error)

            elif auth == 3:
                logger.warning(f"src_ip {ip_source} -> {user.username} user account failed to login")
                return render_template('login.html', title="Login", form=form, login_error=error)

            else:
                logger.warning(f"src_ip {ip_source} -> {user.username} user account has been locked out")
                error = "Account has been locked out. Please contact customer support for assistance."
                return render_template('login.html', title="Login", form=form, login_error=error)
        else:
            return render_template('login.html', title="Login", form=form, login_error=error)
    return render_template('login.html', title="Login", form=form)


@views.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    logger = logging.getLogger('auth_log')
    logger.info(f"src_ip {ip_source} -> {current_user.username} user account successfully logged out")

    logout_user()
    session.clear()
    return redirect(url_for('views.login'))


@views.route('/otp-input', methods=['GET', 'POST'])
def otp_input():
    mmc = MessageManagementController()
    amc = AccountManagementController()

    ip_source = ipaddress.IPv4Address(request.remote_addr)

    logger = logging.getLogger('auth_log')

    if 'username' not in session:
        session.clear()
        return redirect(url_for('views.login'))

    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))
        return redirect(url_for('views.dashboard'))

    form = Token2FAForm(request.form)
    error = "Invalid Token"

    if request.method == 'POST' and form.validate_on_submit():
        amc = AccountManagementController()
        user = User.query.filter_by(username=session['username']).first()

        if user and user.prev_token == escape(form.token.data):
            error = "Something went wrong"
            return render_template('otp-input.html', form=form, login_error=error)

        elif user.is_disabled:
            del session['username']
            form = LoginForm()
            error = "Account has been locked out. Please contact customer support for assistance."
            return render_template('login.html', title="Login", form=form, login_error=error)

        elif user and user.verify_totp(escape(form.token.data)):
            del session['username']
            amc.login_success(user, escape(form.token.data))
            login_user(user)

            if current_user.failed_login_attempts > 0:
                mmc.send_incorrect_attempts(current_user)

            mmc.send_last_login(current_user)

            log_message = f"src_ip {ip_source} -> {current_user.username} logged in on {current_user.last_login.strftime('%Y-%m-%d %H:%M:%S')}"
            logger.info(log_message)

            if current_user.is_admin:
                return redirect(url_for('views.admin_dashboard'))
            if current_user.email_verified is False:
                return redirect(url_for('views.unverified_email'))
            else:
                return redirect(url_for('views.dashboard'))
        else:
            amc.login_fail(user)

            if user.failed_login_attempts > 3:
                logger.warning(f"src_ip {ip_source} -> {user.username} user account has been locked out")

            logger.warning(f"src_ip {ip_source} -> {user.username} user account failed to login")

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

    emc = EmailManagementController()
    amc = AccountManagementController()
    dec_user = amc.decrypt_by_id(current_user.id)

    token = emc.generate_token(current_user.username, current_user)
    confirm_url = url_for('views.confirm_email', token=token, _external=True)

    emc.send_email(dec_user.email, "HX-Bank - Email Verification",
                   render_template('/email_templates/activate.html', confirm_url=confirm_url))
    update_db()
    return redirect(url_for('views.unverified_email'))


@views.route('/reset-identify', methods=['GET', 'POST'])
def reset_identify():
    amc = AccountManagementController()

    selected = request.args.get('type')
    if selected == "pwd":
        session['type'] = "pwd"
    elif selected == "otp":
        session['type'] = "otp"
    else:
        if selected is None:
            if 'type' not in session:
                return redirect(url_for('views.login'))

    form = ResetFormIdentify(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        error = "Identification Failed"

        session['username'] = escape(form.username.data)
        user = amc.decrypt_by_username(username=session['username'])

        if user:
            session['nric'] = user.nric
            session['dob'] = user.dob
            session['flag'] = 1

            if "username" in session and session['type'] == "otp":
                session['email'] = user.email

                if session['nric'] == escape(form.nric.data) and session['dob'] == str(escape(form.dob.data)):
                    del session['nric']
                    del session['dob']
                    return redirect(url_for("views.reset_email_auth"))
                else:
                    session.clear()
                    return redirect(url_for("views.login"))
            elif "username" in session and session['type'] == "pwd":
                if session['nric'] == escape(form.nric.data).upper() and session['dob'] == str(escape(form.dob.data)):
                    del session['dob']
                    del session['nric']
                    return redirect(url_for("views.reset_authenticate"))
                else:
                    del session['nric']
                    del session['dob']
                    del session['flag']
                    del session['username']
                    return render_template('reset-identify.html', form=form, identity_error=error)
            else:
                del session['nric']
                del session['dob']
                del session['flag']
                del session['username']
                error = "An unknown error has occurred"
                return render_template('reset-identify.html', form=form, identity_error=error)
        else:
            del session['username']
            return render_template('reset-identify.html', form=form, identity_error=error)
    return render_template('reset-identify.html', form=form)


@views.route('/reset-email-auth', methods=['GET', 'POST'])
def reset_email_auth():
    if 'flag' not in session:
        session.clear()
        return redirect(url_for("views.login"))
    email = session['email']
    del session['email']
    del session['flag']

    emc = EmailManagementController()

    user = User.query.filter_by(username=session['username']).first()
    token = emc.generate_token(user.username, user)

    confirm_url = url_for('views.confirm_otp', token=token, _external=True)
    emc.send_email(email, "HX-Bank - OTP Reset", render_template('/email_templates/otp.html', confirm_url=confirm_url,
                                                                 time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    session.clear()
    return redirect(url_for('views.reset_success'))


@views.route('/confirm_otp/<token>')
def confirm_otp(token):
    emc = EmailManagementController()

    try:
        username = emc.confirm_token(token)
        user = User.query.filter_by(username=username).first()
        if user.email_token != token:
            abort(404)
        else:
            emc.nullify_token(user)
            return redirect(url_for('views.otp_setup'))
    except:
        abort(404)


@views.route('/reset-authenticate', methods=['GET', 'POST'])
def reset_authenticate():
    if 'flag' not in session:
        session.clear()
        return redirect(url_for("views.login"))

    amc = AccountManagementController()

    if 'username' not in session:
        session.clear()
        return redirect(url_for("views.login"))
    if 'type' not in session:
        session.clear()
        return redirect(url_for("views.login"))
    form = ResetFormAuthenticate(request.form)
    error = "Invalid Token"
    if request.method == 'POST' and form.validate_on_submit():
        del session['flag']
        user = amc.decrypt_by_username(session['username'])
        if user and user.prev_token == escape(form.token.data):
            error = "Something went wrong"
            session['flag'] = 1
            return render_template('reset-authenticate.html', form=form, authenticate_error=error)
        elif user and user.verify_totp(escape(form.token.data)):
            if session['type'] == "pwd":
                del session['type']
                session['flag'] = 1
                return redirect(url_for("views.reset_pwd"))
            else:
                session.clear()
                return redirect(url_for('views.login'))
        else:
            session['flag'] = 1
            return render_template('reset-authenticate.html', form=form, authenticate_error=error)
    return render_template('reset-authenticate.html', form=form)


@views.route('/reset-pwd', methods=['GET', 'POST'])
def reset_pwd():
    if 'flag' not in session:
        session.clear()
        return redirect(url_for("views.login"))
    amc = AccountManagementController()

    if 'username' not in session:
        session.clear()
        return redirect(url_for("views.login"))
    form = ResetPasswordForm(request.form)
    error = "Reset Failed"
    if request.method == 'POST' and form.validate_on_submit():
        del session['flag']
        mmc = MessageManagementController()
        emc = EmailManagementController()
        user = User.query.filter_by(username=session['username']).first()
        dec_user = amc.decrypt_by_username(session['username'])
        if user:
            mmc.send_password_reset(user)
            password = flask_bcrypt.generate_password_hash(form.password.data)
            amc.reset_pwd(user, password)

            emc.send_email(dec_user.email, "HX-Bank - Password Reset",
                           render_template('/email_templates/reset.html', reset="password",
                                           time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            session.clear()
            return redirect(url_for("views.reset_success"))
        else:
            session['flag'] = 1
            return render_template('reset-pwd.html', form=form, reset_error=error)
    return render_template('reset-pwd.html', form=form)


@views.route('/personal-banking/dashboard', methods=['GET'])
@login_required
@check_email_verification
def dashboard():
    amc = AccountManagementController()

    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    user_data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    total_available_balance = user_data.acc_balance - user_data.money_on_hold
    daily_xfer_remain = user_data.acc_xfer_limit - user_data.acc_xfer_daily
    if daily_xfer_remain < 0:
        daily_xfer_remain = 0
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

    user = amc.decrypt_by_username(username=current_user.username)
    firstname, lastname = user.firstname, user.lastname

    msg_data = load_nav_messages()

    return render_template('dashboard.html', title="Dashboard", firstname=firstname, lastname=lastname,
                           data=user_data, msg_data=msg_data, recent_trans=data,
                           available_balance=total_available_balance, xfer_remain=daily_xfer_remain)


@views.route("/admin/admin-dashboard", methods=['GET', 'POST'])
@login_required
@check_email_verification
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('views.dashboard'))

    amc = AccountManagementController()

    form = ManageUserForm()

    if request.method == "POST" and form.validate_on_submit():
        user_acc = User.query.filter_by(id=escape(form.userid.data)).first()

        if user_acc.id == current_user.id:
            return redirect(url_for('views.admin_dashboard'))

        if form.data["unlock"]:
            amc.unlock_account(user_acc)

        elif form.data["disable"]:
            amc.disable_account(user_acc)

        elif form.data["delete"]:
            amc.delete_account(user_acc)

        return redirect(url_for('views.admin_dashboard'))

    user_acc = User.query.all()
    data = []
    for user in user_acc:
        if user.id == current_user.id:
            pass
        else:
            dec_user = amc.decrypt_by_username(user.username)
            data.append({"userid": dec_user.id, "username": dec_user.username, "nric": dec_user.nric[-3:],
                         "email": dec_user.email,
                         "last_login": dec_user.last_login.strftime('%Y-%m-%d %H:%M:%S'), "role": dec_user.is_admin,
                         "is_disabled": dec_user.is_disabled})
    msg_data = load_nav_messages()

    return render_template('/admin/admin-dashboard.html', title="Admin Dashboard", data=data, form=form,
                           msg_data=msg_data)


@views.route("/personal-banking/transfer", methods=['GET', 'POST'])
@login_required
@check_email_verification
def transfer():
    basm = BankAccountManagementController()
    amc = AccountManagementController()

    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    msg_data = load_nav_messages()

    ip_source = ipaddress.IPv4Address(request.remote_addr)

    form = TransferMoneyForm()

    transferee_data = Transferee.query.filter_by(transferer_id=current_user.id).all()
    data = []
    for transferee in transferee_data:
        acc_num = Account.query.filter_by(userid=transferee.transferee_id).first().acc_number
        transferee_user = amc.decrypt_by_id(transferee.transferee_id)
        firstname = transferee_user.firstname
        lastname = transferee_user.lastname
        user_data = f"{acc_num} - {firstname} {lastname}"
        data.append(user_data)
    form.transferee_acc.choices = data

    transferer_acc = Account.query.filter_by(userid=current_user.id).first()

    if request.method == 'POST' and form.validate_on_submit():
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bacm = BankAccountManagementController()

        description = escape(form.description.data)
        amount = float(Decimal(escape(form.amount.data)).quantize(TWO_PLACES))
        transferee_acc_number = escape(form.transferee_acc.data.split(" ")[0])

        error, acc_balance, transferee_user = basm.transfer_money_checks(amount, transferer_acc, transferee_acc_number)
        if error is not None:
            return render_template('transfer.html', title="Transfer", form=form, xfer_error=error, msg_data=msg_data,
                                   balance=acc_balance)

        transferee_userid = transferee_user.acc_number
        transferer_acc = Account.query.filter_by(userid=current_user.id).first()
        transferee_acc = Account.query.filter_by(acc_number=transferee_userid).first()
        require_approval, transferer_acc_number, transferee_acc_number = bacm.create_transaction(amount, transferer_acc,
                                                                                                 transferee_acc,
                                                                                                 description)

        logger = logging.getLogger('user_activity_log')
        logger.info(
            f"src_ip {ip_source} -> {Decimal(amount).quantize(TWO_PLACES)} transferred from {transferer_acc_number} to {transferee_acc_number}")

        dec_user = amc.decrypt_by_id(current_user.id)
        if require_approval:
            emc.send_email(dec_user.email, "HX-Bank - Transfer",
                           render_template('/email_templates/transfer-pending.html',
                                           amount=Decimal(amount).quantize(TWO_PLACES),
                                           acc_num=transferee_acc.acc_number,
                                           time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            mmc.send_pending_transfer(Decimal(amount).quantize(TWO_PLACES), escape(form.transferee_acc.data),
                                      current_user)
            return redirect(url_for('views.approval_required'))

        emc.send_email(dec_user.email, "HX-Bank - Transfer",
                       render_template('/email_templates/transfer-success.html',
                                       amount=Decimal(amount).quantize(TWO_PLACES),
                                       acc_num=transferee_acc.acc_number,
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        mmc.send_success_transfer(Decimal(amount).quantize(TWO_PLACES), escape(form.transferee_acc.data),
                                  current_user)
        return redirect(url_for('views.success'))

    return render_template('transfer.html', title="Transfer", form=form, msg_data=msg_data,
                           balance=Decimal(transferer_acc.acc_balance).quantize(TWO_PLACES))


@views.route("/personal-banking/transfer-onetime", methods=['GET', 'POST'])
@login_required
@check_email_verification
def transfer_onetime():
    basm = BankAccountManagementController()

    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    msg_data = load_nav_messages()

    ip_source = ipaddress.IPv4Address(request.remote_addr)

    form = TransferMoneyOneTimeForm()

    transferrer_userid = current_user.id
    transferer_acc = Account.query.filter_by(userid=transferrer_userid).first()

    if request.method == 'POST' and form.validate_on_submit():
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bacm = BankAccountManagementController()
        amc = AccountManagementController()

        description = escape(form.description.data)
        amount = float(Decimal(escape(form.amount.data)).quantize(TWO_PLACES))
        transferee_acc_number = escape(form.transferee_acc.data.split(" ")[0])

        error, acc_balance, transferee_user = basm.transfer_money_checks(amount, transferer_acc, transferee_acc_number)
        if error is not None:
            return render_template('transfer-onetime.html', title="Transfer-Onetime", form=form, xfer_error=error,
                                   msg_data=msg_data,
                                   balance=acc_balance)

        transferee_userid = transferee_user.acc_number
        transferer_acc = Account.query.filter_by(userid=transferrer_userid).first()
        transferee_acc = Account.query.filter_by(acc_number=transferee_userid).first()
        require_approval, transferer_acc_number, transferee_acc_number = bacm.create_transaction(amount, transferer_acc,
                                                                                                 transferee_acc,
                                                                                                 description)

        logger = logging.getLogger('user_activity_log')
        logger.info(
            f"src_ip {ip_source} -> {Decimal(amount).quantize(TWO_PLACES)} transferred from {transferer_acc_number} to "
            f"{transferee_acc_number}")

        dec_user = amc.decrypt_by_id(current_user.id)
        if require_approval:
            emc.send_email(dec_user.email, "HX-Bank - Transfer",
                           render_template('/email_templates/transfer-pending.html',
                                           amount=Decimal(amount).quantize(TWO_PLACES),
                                           acc_num=transferee_acc.acc_number,
                                           time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            mmc.send_pending_transfer(Decimal(amount).quantize(TWO_PLACES), escape(form.transferee_acc.data),
                                      current_user)
            return redirect(url_for('views.approval_required'))

        emc.send_email(dec_user.email, "HX-Bank - Transfer",
                       render_template('/email_templates/transfer-success.html',
                                       amount=Decimal(amount).quantize(TWO_PLACES),
                                       acc_num=transferee_acc.acc_number,
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        mmc.send_success_transfer(Decimal(amount).quantize(TWO_PLACES), escape(form.transferee_acc.data),
                                  current_user)
        return redirect(url_for('views.success'))

    return render_template('transfer-onetime.html', title="Transfer-Onetime", form=form, msg_data=msg_data,
                           balance=Decimal(transferer_acc.acc_balance).quantize(TWO_PLACES))


@views.route("/personal-banking/add-transferee", methods=['GET', 'POST'])
@login_required
@check_email_verification
def add_transferee():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    msg_data = load_nav_messages()

    ip_source = ipaddress.IPv4Address(request.remote_addr)

    form = AddTransfereeForm()

    if request.method == 'POST' and form.validate_on_submit():
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bamc = BankAccountManagementController()
        amc = AccountManagementController()

        transferee_acc = escape(form.transferee_acc.data)

        add_error = bamc.add_transferee_checks(current_user.id, transferee_acc)
        if add_error is not None:
            return render_template('add-transferee.html', title="Add Transferee", form=form, add_error=add_error,
                                   msg_data=msg_data)

        bamc.add_transferee(transferee_acc)

        dec_user = amc.decrypt_by_id(current_user.id)
        mmc.send_add_acc_no(transferee_acc.acc_number, current_user)
        emc.send_email(dec_user.email, "HX-Bank - Add Recipient",
                       render_template('/email_templates/recipient.html', recipient=transferee_acc.acc_number,
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        logger = logging.getLogger('user_activity_log')
        logger.info(
            f"src_ip {ip_source} -> {current_user.username} has added {transferee_acc.acc_number} as a transferee")

        return redirect(url_for('views.success'))

    return render_template('add-transferee.html', title="Add Transferee", form=form, msg_data=msg_data)


@views.route("/personal-banking/transaction-history", methods=['GET', 'POST'])
@login_required
@check_email_verification
def transaction_history():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    msg_data = load_nav_messages()

    bamc = BankAccountManagementController()

    data = bamc.transaction_history(current_user.id)

    return render_template('transaction-history.html', title="Transaction History", data=data, msg_data=msg_data)


@views.route("/personal-banking/view-transferee", methods=['GET', 'POST'])
@login_required
@check_email_verification
def view_transferee():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    msg_data = load_nav_messages()

    form = RemoveTransfereeForm()

    bamc = BankAccountManagementController()

    form.transferee_acc.choices, data = bamc.view_transferee(current_user.id)

    if request.method == "POST" and form.validate_on_submit():
        bamc.remove_transferee(escape(form.transferee_acc.data.split(" ")[0]))
        return redirect(url_for('views.success'))
    return render_template('view-transferee.html', title="View Transferee", form=form, data=data, msg_data=msg_data)


@views.route("/personal-banking/set-transfer-limit", methods=['GET', 'POST'])
@login_required
@check_email_verification
def set_transfer_limit():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    msg_data = load_nav_messages()

    ip_source = ipaddress.IPv4Address(request.remote_addr)

    user_acc = Account.query.filter_by(userid=current_user.id).first()

    form = SetTransferLimitForm()

    if request.method == 'POST' and form.validate_on_submit():
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bamc = BankAccountManagementController()
        amc = AccountManagementController()

        amount = float(Decimal(escape(form.transfer_limit.data)).quantize(TWO_PLACES))

        set_status = bamc.set_transfer_limit(current_user.id, amount)
        if set_status is not None:
            return render_template('set-transfer-limit.html', title="Set Transfer Limit", form=form, msg_data=msg_data,
                                   limit_error=set_status,
                                   current_limit=Decimal(user_acc.acc_xfer_limit).quantize(TWO_PLACES))

        mmc.send_transfer_limit(Decimal(amount).quantize(TWO_PLACES), current_user)
        dec_user = amc.decrypt_by_id(current_user.id)
        emc.send_email(dec_user.email, "HX-Bank - New Transfer Limit",
                       render_template('/email_templates/transfer-limit.html',
                                       amount=Decimal(amount).quantize(TWO_PLACES),
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        logger = logging.getLogger('user_activity_log')
        logger.info(f"src_ip {ip_source} -> {current_user.username} has updated transfer limit to ${amount}")

        return redirect(url_for('views.success'))

    return render_template('set-transfer-limit.html', title="Set Transfer Limit", form=form, msg_data=msg_data,
                           current_limit=Decimal(user_acc.acc_xfer_limit).quantize(TWO_PLACES))


@views.route("/personal-banking/topup-balance", methods=['GET', 'POST'])
@login_required
@check_email_verification
def topup_balance():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    msg_data = load_nav_messages()

    ip_source = ipaddress.IPv4Address(request.remote_addr)

    form = TopUpForm()

    if request.method == 'POST' and form.validate_on_submit():
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bamc = BankAccountManagementController()
        amc = AccountManagementController()

        amount = float(Decimal(escape(form.amount.data)).quantize(TWO_PLACES))
        description = f"Self-service top up of ${Decimal(amount).quantize(TWO_PLACES)}"

        user_acc = db.session.query(Account).join(User).filter(User.id == current_user.id).first().acc_number
        error = bamc.topup_balance(current_user.id, user_acc, amount, description)

        if error is not None:
            return render_template('topup.html', title="Top Up", form=form, msg_data=msg_data, topup_error=error)

        mmc.send_top_up(Decimal(amount).quantize(TWO_PLACES), current_user)
        dec_user = amc.decrypt_by_id(current_user.id)
        emc.send_email(dec_user.email, "HX-Bank - Top Up",
                       render_template('/email_templates/top-up.html', amount=Decimal(amount).quantize(TWO_PLACES),
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        logger = logging.getLogger('user_activity_log')
        logger.info(f"src_ip {ip_source} -> {current_user.username} has topped up {amount}")

        return redirect(url_for('views.success'))
    return render_template('topup.html', title="Top Up", form=form, msg_data=msg_data)


@views.route("/communication/message-center", methods=['GET', 'POST'])
@login_required
@check_email_verification
def message_center():
    mmc = MessageManagementController()

    msg_data = load_nav_messages()

    form = SecureMessageForm()
    if request.method == 'POST' and form.validate_on_submit():
        msg = db.session.query(Message).filter_by(id=escape(form.msg.data)).first()
        if msg:
            check = db.session.query(Message).join(User).filter(msg.userid == current_user.id).first()
        else:
            error = "Something went wrong"
            return render_template('message-center.html', title="Secure Message Center", msg_data=msg_data, form=form,
                                   msg_error=error)
        if check:
            if form.data["mark"]:
                mmc.mark_message(msg)

            elif form.data["unmark"]:
                mmc.unmark_message(msg)

            elif form.data["delete"]:
                mmc.del_messasge(msg)
        else:
            error = "Something went wrong"
            return render_template('message-center.html', title="Secure Message Center", msg_data=msg_data, form=form,
                                   msg_error=error)
        return redirect(url_for('views.message_center'))
    return render_template('message-center.html', title="Secure Message Center", msg_data=msg_data, form=form)


@views.route("/admin/transaction-management", methods=["GET", "POST"])
@login_required
@check_email_verification
def transaction_management():
    if not current_user.is_admin:
        return redirect(url_for('views.dashboard'))
    form = ApproveTransactionForm()

    if request.method == "POST" and form.validate_on_submit():
        transaction = Transaction.query.filter_by(id=escape(form.transactionid.data)).first()

        transferrer_acc = Account.query.filter_by(acc_number=transaction.transferrer_acc_number).first()

        if escape(form.approve.data):
            transferee_acc = Account.query.filter_by(acc_number=transaction.transferee_acc_number).first()
            transferee_acc.acc_balance += transferrer_acc.money_on_hold
            transferrer_acc.acc_balance -= transferrer_acc.money_on_hold
            transferrer_acc.money_on_hold -= transferrer_acc.money_on_hold
            transaction.status = 0
            transaction.require_approval = False
            update_db_no_close()

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


@views.route("/account_management/account-settings", methods=['GET', 'POST'])
@login_required
@check_email_verification
def acc_settings():
    data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    msg_data = load_nav_messages()
    if current_user.is_admin:
        return render_template('account-settings.html', title="Admin settings", data=data, msg_data=msg_data)
    return render_template('account-settings.html', title="User settings", data=data, msg_data=msg_data)


@views.route('/account-management/change-pwd', methods=['GET', 'POST'])
@login_required
@check_email_verification
def change_pwd():
    amc = AccountManagementController()

    msg_data = load_nav_messages()
    form = ChangePasswordForm()
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    if request.method == 'POST' and form.validate_on_submit():
        mmc = MessageManagementController()
        emc = EmailManagementController()
        user = User.query.filter_by(username=current_user.username).first()
        if user:
            if user.prev_token == form.token.data:
                error = "Something went wrong"
                return render_template('change-pwd.html', form=form, reset_error=error, msg_data=msg_data)
            if flask_bcrypt.check_password_hash(user.password_hash, form.current_password.data) and user.verify_totp(
                    escape(form.token.data)):

                password = flask_bcrypt.generate_password_hash(form.password.data)
                amc.change_pw(user, password)

                dec_user = amc.decrypt_by_id(current_user.id)
                emc.send_email(dec_user.email, "HX-Bank - Password Change",
                               render_template('/email_templates/reset.html', reset="password",
                                               time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                mmc.send_password_change(user)

                logger = logging.getLogger('user_activity_log')
                logger.info(f"src_ip {ip_source} -> {current_user.username} has changed their password")

                return redirect(url_for("views.acc_settings"))
            else:
                error = "Incorrect OTP"
                return render_template('change-pwd.html', form=form, reset_error=error, msg_data=msg_data)
    return render_template('change-pwd.html', form=form, msg_data=msg_data)


@views.route('/account-management/change-otp', methods=['GET', 'POST'])
@login_required
@check_email_verification
def change_otp():
    msg_data = load_nav_messages()
    form = Token2FAForm()
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    error = "Invalid Token"
    if request.method == 'POST' and form.validate_on_submit():
        if current_user.prev_token == escape(form.token.data):
            error = "Something went wrong"
            return render_template('auth-change-otp.html', form=form, msg_data=msg_data, otp_error=error)
        elif current_user.verify_totp(escape(form.token.data)):
            logger = logging.getLogger('user_activity_log')
            logger.info(f"src_ip {ip_source} -> {current_user.username} has updated their OTP")
            session['flag'] = 1
            return redirect(url_for("views.auth_otp_reset"))
        else:
            return render_template('auth-change-otp.html', form=form, msg_data=msg_data, otp_error=error)
    return render_template('auth-change-otp.html', form=form, msg_data=msg_data)


@views.route('/account-management/otp-setup', methods=['GET'])
@login_required
@check_email_verification
def auth_otp_reset():
    if 'flag' not in session:
        return redirect(url_for("views.acc_settings"))
    del session['flag']
    msg_data = load_nav_messages()
    return render_template('change-otp.html', msg_data=msg_data), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@views.route('/account-management/qrcode', methods=['GET'])
@login_required
@check_email_verification
def auth_qrcode():
    amc = AccountManagementController()
    amc.generate_pyotp(current_user)
    mmc = MessageManagementController()
    emc = EmailManagementController()
    dec_user = amc.decrypt_by_id(current_user.id)
    if current_user.prev_token is not None:
        emc.send_email(dec_user.email, "HX-Bank - OTP Reset",
                       render_template('/email_templates/reset.html', reset="OTP",
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        mmc.send_otp_reset(current_user)
    url = pyqrcode.create(current_user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@views.route("/reset_successful")
def reset_success():
    return render_template('reset-successful.html', title="Reset Successful")


@views.route("/success")
@login_required
@check_email_verification
def success():
    msg_data = load_nav_messages()
    return render_template('success.html', title="Success", msg_data=msg_data)


@views.route("/enrolment-successful")
@login_required
@check_email_verification
def enrolment_success():
    return render_template('/admin/enrolment-successful.html', title="Success")


@views.route("/approval-required")
@login_required
@check_email_verification
def approval_required():
    msg_data = load_nav_messages()
    return render_template('approval-required.html', title="Approval Required", msg_data=msg_data)


@views.route("/robots.txt", methods=['GET'])
def robots():
    return render_template('robots.txt', title="Robots")


@views.route("/api/acc-overview", methods=['GET'])
@login_required
@check_email_verification
def acc_overview():
    if current_user.is_admin:
        abort(403)
    data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    if data:
        acc_balance_on_hold = Decimal(data.acc_balance - data.money_on_hold).quantize(TWO_PLACES)
        acc_xfer_daily = Decimal(data.acc_xfer_limit - data.acc_xfer_daily).quantize(TWO_PLACES)
        if acc_xfer_daily < 0:
            acc_xfer_daily = 0
        return jsonify({'acc_balance': Decimal(data.acc_balance).quantize(TWO_PLACES),
                        'acc_balance_on_hold': acc_balance_on_hold,
                        'acc_xfer_limit': Decimal(data.acc_xfer_limit).quantize(TWO_PLACES),
                        'acc_xfer_daily': acc_xfer_daily}), 200


@views.route("/api/barchart-graph", methods=['GET'])
@login_required
@check_email_verification
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
@check_email_verification
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
@check_email_verification
def profile():
    amc = AccountManagementController()

    user = amc.decrypt_by_username(username=current_user.username)

    acc_info = Account.query.filter_by(userid=current_user.id).first()

    msg_data = load_nav_messages()

    return render_template('profile.html', title="Profile Page", user=user, msg_data=msg_data, acc_info=acc_info)


@views.route("/admin/enrol-admin", methods=['GET', 'POST'])
@login_required
@check_email_verification
def enrol_admin():
    if current_user.is_admin:
        ip_source = ipaddress.IPv4Address(request.remote_addr)

        form = RegisterForm()
        if request.method == 'POST' and form.validate_on_submit():
            mmc = MessageManagementController()
            emc = EmailManagementController()
            amc = AccountManagementController()

            username = escape(form.username.data)
            firstname = escape(form.firstname.data)
            lastname = escape(form.lastname.data)
            address = escape(form.address.data)
            email = escape(form.email.data)
            mobile = escape(form.mobile.data)
            nric = escape(form.nric.data.upper())
            dob = form.dob.data
            age = date.today().year - dob.year
            password = flask_bcrypt.generate_password_hash(form.password.data)

            check, register_error = amc.verify_details(username, email, mobile, nric, dob, age)
            if check:
                return render_template('/admin/enrol-admin.html', title="Register", form=form,
                                       register_error=register_error)

            logger = logging.getLogger('user_activity_log')

            amc.add_user(username, firstname, lastname, address, email, mobile, nric, dob, password, None, None, 1)

            logger.info(f"src_ip {ip_source} -> {username} admin account created")

            user = amc.decrypt_by_username(username)

            token = emc.generate_token(user.username, user)

            confirm_url = url_for('views.confirm_email', token=token, _external=True)
            emc.send_email(email, "HX-Bank - Email Verification",
                           render_template('/email_templates/activate.html', confirm_url=confirm_url))

            logout_user()
            session.clear()
            session['username'] = username

            return redirect(url_for("views.otp_setup"))
        return render_template('/admin/enrol-admin.html', title="Register Admin", form=form)

    return redirect(url_for('views.login'))


@views.before_request
def make_session_permanent():
    session.permanent = True


@views.after_request
def add_header(r):
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['X-Content-Type-Options'] = 'nosniff'
    return r