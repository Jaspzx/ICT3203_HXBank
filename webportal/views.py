import pyqrcode
import logging
import ipaddress
from decimal import Decimal
from io import BytesIO
from .utils.interact_db import *
from flask import Blueprint, redirect, url_for, render_template, request, session, abort, jsonify, escape
from flask_login import login_required, login_user, logout_user
from webportal import flask_bcrypt, login_manager
from webportal.models.Transferee import *
from .forms import *
from .utils.messaging import *
from functools import wraps
from webportal.controllers.MessageManagementController import MessageManagementController
from webportal.controllers.AccountManagementController import AccountManagementController
from webportal.controllers.EmailManagementController import EmailManagementController
from webportal.controllers.BankAccountManagementController import BankAccountManagementController

# Global variables. 
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
    # Get the source ip address. 
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Check that the current user is authenticated. 
    if current_user.is_authenticated:
        # Return the admin view. 
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))

        # Return the user view. 
        return redirect(url_for('views.dashboard'))

    # Populate the register from. 
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        # Initiate the controllers. 
        mmc = MessageManagementController()
        emc = EmailManagementController()
        amc = AccountManagementController()
        bamc = BankAccountManagementController()

        # Sanitise user information.
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

        # Verify user information.
        check, register_error = amc.verify_details(username, email, mobile, nric, dob, age)
        if check:
            return render_template('register.html', title="Register", form=form, register_error=register_error)

        # Get the user activity logger. 
        logger = logging.getLogger('user_activity_log')

        # Create the user account.
        amc.add_user(username, firstname, lastname, address, email, mobile, nric, dob, password, None, None)

        # Log the user's activity.
        logger.info(f"src_ip {ip_source} -> {username} user account created")
        user = User.query.filter_by(username=username).first()
        token = emc.generate_token(email, user)

        # Create a bank acc for the newly created user.
        random_gen = SystemRandom()
        welcome_amt = random_gen.randrange(1000, 10000)
        acc_number = "".join([str(random_gen.randrange(9)) for i in range(10)])
        bamc.add_bank_account(user.id, welcome_amt, acc_number)

        # Send welcome message.
        mmc.send_welcome_msg(welcome_amt, user)

        # Logging.
        logger.info(f"src_ip {ip_source} -> Bank acc {acc_number} created and linked to {username}")

        # Create the user's session and redirect to verify email. 
        session['username'] = username
        confirm_url = url_for('views.confirm_email', token=token, _external=True)
        emc.send_email(email, "HX-Bank - Email Verification",
                       render_template('/email_templates/activate.html', confirm_url=confirm_url))

        # Return OTP setup page.
        return redirect(url_for("views.otp_setup"))
    return render_template('register.html', title="Register", form=form)


@views.route('/confirm/<token>')
def confirm_email(token):
    # Initiate the controller.
    emc = EmailManagementController()

    # Check that the verification code provided by user matches. 
    try:
        email = emc.confirm_token(token)

        # Verify email token.
        if emc.verify_token(email, token):
            return redirect(url_for('views.login'))
        else:
            abort(404)
    except:
        abort(404)


@views.route('/otp-setup')
def otp_setup():
    # Redirect to login if user is invalid. 
    if 'username' not in session:
        return redirect(url_for('views.login'))

    # Redirect to user's dashboard if user is authenticated. 
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))

    # Double check that the user exists. 
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('views.login'))

    # Return page to setup OTP. 
    return render_template('otp-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@views.route('/qrcode')
def qrcode():
    # Initiate the controllers.
    mmc = MessageManagementController()
    emc = EmailManagementController()
    amc = AccountManagementController()

    # Abort if the username is invalid. 
    if 'username' not in session:
        abort(404)

    # Redirect to user's dashboard if authenticated. 
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))

    # Dobule check that the user is valid. 
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # Generate the pyotp secret. 
    amc.generate_pyotp(user)

    # 
    if user.prev_token is not None:
        emc.send_email(user.email, "HX-Bank - OTP Reset",
                       render_template('/email_templates/reset.html', reset="OTP",
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        mmc.send_otp_reset(user)
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
    # Initiate the controller.
    amc = AccountManagementController()

    # Get the source ip address. 
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Get the auth logger. 
    logger = logging.getLogger('auth_log')
    if current_user.is_authenticated:
        # Log the user activity.
        logger.info(f"src_ip {ip_source} -> {current_user.username} user account successfully logged in")

        # Redirect to admin dashboard if user is admin.
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))

        # Redirect to the user's dashboard. 
        return redirect(url_for('views.dashboard'))

    # Initiate the login form. 
    form = LoginForm()
    error = "Login Failed"

    # Populate the login form and validate the form. 
    if request.method == 'POST' and form.validate_on_submit():

        # Sanitise the data. 
        user = User.query.filter_by(username=escape(form.username.data)).first()
        password = form.password.data

        # Authenticate the user.
        if user:
            auth = amc.authenticate(user, password)

            # Authentication is successful. 
            if auth == 1:
                session['username'] = user.username
                return redirect(url_for('views.otp_input'))

            # User account has been locked. 
            elif auth == 2:
                error = "Account has been locked out. Please contact customer support for assistance."
                return render_template('login.html', title="Login", form=form, login_error=error)

            # User failed to authenticate. 
            elif auth == 3:
                logger.warning(f"src_ip {ip_source} -> {user.username} user account failed to login")

            # User account has been locked. 
            else:
                logger.warning(f"src_ip {ip_source} -> {user.username} user account has been locked out")
                return render_template('login.html', title="Login", form=form, login_error=error)
        else:
            return render_template('login.html', title="Login", form=form, login_error=error)
    return render_template('login.html', title="Login", form=form)


@views.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    # Get the source ip address. 
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Log the user activity .
    logger = logging.getLogger('auth_log')
    logger.info(f"src_ip {ip_source} -> {current_user.username} user account successfully logged out")

    # Log out the user. 
    logout_user()
    session.clear()
    return redirect(url_for('views.login'))


@views.route('/otp-input', methods=['GET', 'POST'])
def otp_input():
    # Initiate the controller. 
    mmc = MessageManagementController()

    # Get the source ip address.
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Get the auth logger. 
    logger = logging.getLogger('auth_log')

    if 'username' not in session:
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

            # Logging.
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
                # Logging.
                logger.warning(f"src_ip {ip_source} -> {user.username} user account has been locked out")
            # Logging.
            logger.warning(f"src_ip {ip_source} -> {user.username} user account failed to login")
            return render_template('otp-input.html', form=form, login_error=error)
    return render_template('otp-input.html', form=form)


@views.route('/unverified-email', methods=['GET'])
@login_required
def unverified_email():
    # Check that the current user's email is verified. 
    if current_user.email_verified:

        # Redirect to admin dashboard if user has admin privileges.
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))

        # Redirect to user dashboard if user has normal privileges. 
        else:
            return redirect(url_for('views.dashboard'))
    return render_template('verify-email.html')


@views.route('/resend-verification', methods=['GET'])
@login_required
def resend_verification():
    # Check that the current user's email is verified.
    if current_user.email_verified:
        # Redirect to admin dashboard if user has admin privileges.
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))

        # Redirect to user dashboard if user has normal privileges. 
        else:
            return redirect(url_for('views.dashboard'))

    # Initiate the controller. 
    emc = EmailManagementController()
    token = emc.generate_token(current_user.email, current_user)
    current_user.token = token
    confirm_url = url_for('views.confirm_email', token=token, _external=True)
    emc.send_email(current_user.email, "HX-Bank - Email Verification",
                   render_template('/email_templates/activate.html', confirm_url=confirm_url))
    update_db()
    return redirect(url_for('views.unverified_email'))


@views.route('/reset-identify', methods=['GET', 'POST'])
def reset_identify():
    # Get the info that the user would want to reset.
    selected = request.args.get('type')
    if selected == "pwd":
        session['type'] = "pwd"
    elif selected == "otp":
        session['type'] = "otp"
    else:
        if selected is None:
            if 'type' not in session:
                return redirect(url_for('views.login'))

    # Initiate the form to identify the user.
    form = ResetFormIdentify(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        error = "Identification Failed"

        # Check that the user exists.
        user = User.query.filter_by(nric=escape(form.nric.data.upper())).first()
        if user:
            session['nric'] = user.nric
            session['dob'] = user.dob

            # Reset the username.
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
    emc = EmailManagementController()

    # Generate email token.
    user = User.query.filter_by(username=session['username']).first()
    token = emc.generate_token(email, user)

    # Email the reset OTP page.
    confirm_url = url_for('views.confirm_otp', token=token, _external=True)
    emc.send_email(email, "HX-Bank - OTP Reset", render_template('/email_templates/otp.html', confirm_url=confirm_url,
                                                                 time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    return redirect(url_for('views.login'))


@views.route('/confirm_otp/<token>')
def confirm_otp(token):
    # Initiate the controller.
    emc = EmailManagementController()
    try:
        email = emc.confirm_token(token)
        user = User.query.filter_by(email=email).first()
        if user.email_token != token:
            abort(404)
        else:
            emc.nullify_token(user)
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
        if user and user.prev_token == escape(form.token.data):
            error = "Something went wrong"
            return render_template('otp-input.html', form=form, authenticate_error=error)
        elif user and user.verify_totp(escape(form.token.data)):
            if session['type'] == "pwd":
                del session['type']
                return redirect(url_for("views.reset_pwd"))
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
        mmc = MessageManagementController()
        emc = EmailManagementController()
        user = User.query.filter_by(nric=session['nric']).first()
        if user:
            del session['nric']

            # Reset the user password.
            mmc.send_password_reset(user)
            password = flask_bcrypt.generate_password_hash(form.password.data)
            reset_pwd(user, password)

            # Send the password reset link.
            emc.send_email(user.email, "HX-Bank - Password Reset",
                           render_template('/email_templates/reset.html', reset="password",
                                           time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            return redirect(url_for("views.login"))
        else:
            return render_template('reset-pwd.html', form=form, reset_error=error)
    return render_template('reset-pwd.html', form=form)


@views.route('/personal-banking/dashboard', methods=['GET'])
@login_required
# @check_email_verification
def dashboard():
    # Redirect to admin dashboard if user has admin privileges.
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    # Get the user's bank account details.
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

    # Load the messages.
    msg_data = load_nav_messages()

    # Redirect to the dashboard.
    return render_template('dashboard.html', title="Dashboard", data=user_data, msg_data=msg_data, recent_trans=data,
                           available_balance=total_available_balance, xfer_remain=daily_xfer_remain)


@views.route("/admin/admin-dashboard", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def admin_dashboard():
    # Redirect users to the normal dashboard if they do not have admin privileges.
    if not current_user.is_admin:
        return redirect(url_for('views.dashboard'))

    # Initiate the controller.
    amc = AccountManagementController()

    # Initiate the manager user form.
    form = ManageUserForm()

    # Unlock or disable account depending on the admin's actions.
    if request.method == "POST" and form.validate_on_submit():
        user_acc = User.query.filter_by(id=escape(form.userid.data)).first()

        # Unlock the account.
        if form.data["unlock"]:
            amc.unlock_account(user_acc)

        # Disable the account.
        elif form.data["disable"]:
            amc.disable_account(user_acc)

        return redirect(url_for('views.admin_dashboard'))

    # Get all of the user's data.
    user_acc = User.query.filter_by(is_admin=False).all()
    data = []
    for user in user_acc:
        data.append({"userid": user.id, "username": user.username, "nric": user.nric[-3:], "email": user.email,
                     "last_login": user.last_login.strftime('%Y-%m-%d %H:%M:%S'), "is_disabled": user.is_disabled})
    msg_data = load_nav_messages()

    # Redirect to the admin dashboard.
    return render_template('/admin/admin-dashboard.html', title="Admin Dashboard", data=data, form=form,
                           msg_data=msg_data)


@views.route("/personal-banking/transfer", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def transfer():
    # Initiate controllers.
    basm = BankAccountManagementController()

    # Redirect users to the admin dashboard if they have admin privileges.
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    # Load the messages.
    msg_data = load_nav_messages()

    # Get the source ip address.
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Init the TransferMoneyForm
    form = TransferMoneyForm()

    # Dynamically populate the TransferMoneyForm.
    form.transferee_acc.choices = basm.populate_transfer_money_form(current_user.id)

    # Get the transferrer's account information.
    transferrer_userid = current_user.id
    transferer_acc = Account.query.filter_by(userid=transferrer_userid).first()

    # Check if the form was submitted.
    if request.method == 'POST' and form.validate_on_submit():
        # Initalise the controllers.
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bacm = BankAccountManagementController()

        # Sanitise data.
        description = escape(form.description.data)
        amount = float(Decimal(escape(form.amount.data)).quantize(TWO_PLACES))
        transferee_acc_number = escape(form.transferee_acc.data.split(" ")[0])

        # Perform checks.
        error, acc_balance = basm.transfer_money_checks(amount, transferer_acc)

        if error is not None:
            return render_template('transfer.html', title="Transfer", form=form, xfer_error=error, msg_data=msg_data,
                                   balance=acc_balance)

        # Create a transaction.
        transferee_userid = Account.query.filter_by(acc_number=transferee_acc_number).first().userid
        transferee_user = User.query.filter_by(id=transferee_userid).first()
        transferer_acc = Account.query.filter_by(userid=transferrer_userid).first()
        transferee_acc = Account.query.filter_by(userid=transferee_userid).first()
        require_approval, transferer_acc_number, transferee_acc_number = bacm.create_transaction(amount, transferer_acc,
                                                                                                 transferee_acc,
                                                                                                 description)

        # Logging.
        logger = logging.getLogger('user_activity_log')
        logger.info(
            f"src_ip {ip_source} -> {Decimal(amount).quantize(TWO_PLACES)} transferred from {transferer_acc_number} to {transferee_acc_number}")

        # Return approval required page.
        if require_approval:
            emc.send_email(current_user.email, "HX-Bank - Transfer",
                           render_template('/email_templates/transfer-pending.html',
                                           amount=Decimal(amount).quantize(TWO_PLACES),
                                           acc_num=transferee_acc.acc_number,
                                           time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            mmc.send_pending_transfer(Decimal(amount).quantize(TWO_PLACES), escape(form.transferee_acc.data),
                                      transferee_user)
            return redirect(url_for('views.approval_required'))

        # Return success page.
        emc.send_email(current_user.email, "HX-Bank - Transfer",
                       render_template('/email_templates/transfer-success.html',
                                       amount=Decimal(amount).quantize(TWO_PLACES),
                                       acc_num=transferee_acc.acc_number,
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        mmc.send_success_transfer(Decimal(amount).quantize(TWO_PLACES), escape(form.transferee_acc.data),
                                  transferee_user)
        return redirect(url_for('views.success'))

    # Render the HTML template.
    return render_template('transfer.html', title="Transfer", form=form, msg_data=msg_data,
                           balance=Decimal(transferer_acc.acc_balance).quantize(TWO_PLACES))


@views.route("/personal-banking/transfer-onetime", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def transfer_onetime():
    # Initiate controllers.
    basm = BankAccountManagementController()

    # Redirect users to the admin dashboard if they have admin privileges.
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    # Load the messages.
    msg_data = load_nav_messages()

    # Get the source ip address.
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Init the TransferMoneyForm
    form = TransferMoneyOneTimeForm()

    # Get the transferrer's account information.
    transferrer_userid = current_user.id
    transferer_acc = Account.query.filter_by(userid=transferrer_userid).first()

    # Check if the form was submitted.
    if request.method == 'POST' and form.validate_on_submit():
        # Initalise the controllers.
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bacm = BankAccountManagementController()

        # Sanitise data.
        description = escape(form.description.data)
        amount = float(Decimal(escape(form.amount.data)).quantize(TWO_PLACES))
        transferee_acc_number = escape(form.transferee_acc.data.split(" ")[0])

        # Perform checks.
        error, acc_balance = basm.transfer_money_checks(amount, transferer_acc)
        if error is not None:
            return render_template('transfer-onetime.html', title="Transfer-Onetime", form=form, xfer_error=error,
                                   msg_data=msg_data,
                                   balance=acc_balance)

        # Create a transaction.
        transferee_userid = Account.query.filter_by(acc_number=transferee_acc_number).first().userid
        transferee_user = User.query.filter_by(id=transferee_userid).first()
        transferer_acc = Account.query.filter_by(userid=transferrer_userid).first()
        transferee_acc = Account.query.filter_by(userid=transferee_userid).first()
        require_approval, transferer_acc_number, transferee_acc_number = bacm.create_transaction(amount, transferer_acc,
                                                                                                 transferee_acc,
                                                                                                 description)

        # Logging.
        logger = logging.getLogger('user_activity_log')
        logger.info(
            f"src_ip {ip_source} -> {Decimal(amount).quantize(TWO_PLACES)} transferred from {transferer_acc_number} to {transferee_acc_number}")

        # Return approval required page.
        if require_approval:
            emc.send_email(current_user.email, "HX-Bank - Transfer",
                           render_template('/email_templates/transfer-pending.html',
                                           amount=Decimal(amount).quantize(TWO_PLACES),
                                           acc_num=transferee_acc.acc_number,
                                           time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            mmc.send_pending_transfer(Decimal(amount).quantize(TWO_PLACES), escape(form.transferee_acc.data),
                                      transferee_user)
            return redirect(url_for('views.approval_required'))

        # Return success page.
        emc.send_email(current_user.email, "HX-Bank - Transfer",
                       render_template('/email_templates/transfer-success.html',
                                       amount=Decimal(amount).quantize(TWO_PLACES),
                                       acc_num=transferee_acc.acc_number,
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        mmc.send_success_transfer(Decimal(amount).quantize(TWO_PLACES), escape(form.transferee_acc.data),
                                  transferee_user)
        return redirect(url_for('views.success'))

    # Render the HTML template.
    return render_template('transfer-onetime.html', title="Transfer-Onetime", form=form, msg_data=msg_data,
                           balance=Decimal(transferer_acc.acc_balance).quantize(TWO_PLACES))


@views.route("/personal-banking/add-transferee", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def add_transferee():
    # Redirect users to the admin dashboard if they have admin privileges.
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    # Load messages.
    msg_data = load_nav_messages()

    # Get the source ip address.
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Initialise the form.
    form = AddTransfereeForm()

    if request.method == 'POST' and form.validate_on_submit():
        # Initialise the controllers.
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bamc = BankAccountManagementController()

        # Sanitise data.
        transferee_acc = Account.query.filter_by(acc_number=escape(form.transferee_acc.data)).first()

        # Add transferee checks.
        add_error = bamc.add_transferee_checks(current_user.id, transferee_acc)
        if add_error is not None:
            return render_template('add-transferee.html', title="Add Transferee", form=form, add_error=add_error,
                                   msg_data=msg_data)

        # Add transferee.
        bamc.add_transferee(current_user.id, transferee_acc)

        # Create message and send email.
        mmc.send_add_acc_no(transferee_acc.acc_number, current_user)
        emc.send_email(current_user.email, "HX-Bank - Add Recipient",
                       render_template('/email_templates/recipient.html', recipient=transferee_acc.acc_number,
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        # Log to user activity log.
        logger = logging.getLogger('user_activity_log')
        logger.info(
            f"src_ip {ip_source} -> {current_user.username} has added {transferee_acc.acc_number} as a transferee")

        return redirect(url_for('views.success'))

    return render_template('add-transferee.html', title="Add Transferee", form=form, msg_data=msg_data)


@views.route("/personal-banking/transaction-history", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def transaction_history():
    # Redirect users with admin privileges.
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    # Load messages.
    msg_data = load_nav_messages()

    # Initalise controller.
    bamc = BankAccountManagementController()

    # Get transaction history.
    data = bamc.transaction_history(current_user.id)

    # Render template.
    return render_template('transaction-history.html', title="Transaction History", data=data, msg_data=msg_data)


@views.route("/personal-banking/view-transferee", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def view_transferee():
    # Redirect users with admin privileges.
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    # Load messages.
    msg_data = load_nav_messages()

    # Init the RemoveTransferForm.
    form = RemoveTransfereeForm()

    # Initialise controller.
    bamc = BankAccountManagementController()

    # Populate transferee list.
    form.transferee_acc.choices, data = bamc.view_transferee(current_user.id)

    # Check if the remove transferee form was submitted.
    if request.method == "POST" and form.validate_on_submit():
        bamc.remove_transferee(escape(form.transferee_acc.data.split(" ")[0]))
        return redirect(url_for('views.success'))
    return render_template('view-transferee.html', title="View Transferee", form=form, data=data, msg_data=msg_data)


@views.route("/personal-banking/set-transfer-limit", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def set_transfer_limit():
    # Redirect users with admin privileges.
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    # Load messages.
    msg_data = load_nav_messages()

    # Get the source ip address.
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Get account information from the login user.
    user_acc = Account.query.filter_by(userid=current_user.id).first()

    # Init the SetTransferLimitForm.
    form = SetTransferLimitForm()

    if request.method == 'POST' and form.validate_on_submit():
        # Initalise the controllers.
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bamc = BankAccountManagementController()

        #
        amount = float(Decimal(escape(form.transfer_limit.data)).quantize(TWO_PLACES))

        # Set the transfer limit.
        set_status = bamc.set_transfer_limit(current_user.id, amount)
        if set_status is not None:
            return render_template('set-transfer-limit.html', title="Set Transfer Limit", form=form, msg_data=msg_data,
                                   limit_error=set_status,
                                   current_limit=Decimal(user_acc.acc_xfer_limit).quantize(TWO_PLACES))

        #
        mmc.send_transfer_limit(Decimal(amount).quantize(TWO_PLACES), current_user)
        emc.send_email(current_user.email, "HX-Bank - New Transfer Limit",
                       render_template('/email_templates/transfer-limit.html',
                                       amount=Decimal(amount).quantize(TWO_PLACES),
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        # Logging.
        logger = logging.getLogger('user_activity_log')
        logger.info(f"src_ip {ip_source} -> {current_user.username} has updated transfer limit to ${amount}")

        return redirect(url_for('views.success'))

    return render_template('set-transfer-limit.html', title="Set Transfer Limit", form=form, msg_data=msg_data,
                           current_limit=Decimal(user_acc.acc_xfer_limit).quantize(TWO_PLACES))


@views.route("/personal-banking/topup-balance", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def topup_balance():
    # Redirect users with admin privileges.
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    # Load messages.
    msg_data = load_nav_messages()

    # Get the source ip address.
    ip_source = ipaddress.IPv4Address(request.remote_addr)

    # Initalise the topupform.
    form = TopUpForm()

    if request.method == 'POST' and form.validate_on_submit():
        # Initalise the controllers.
        mmc = MessageManagementController()
        emc = EmailManagementController()
        bamc = BankAccountManagementController()

        # Sanitise data.
        amount = float(Decimal(escape(form.amount.data)).quantize(TWO_PLACES))
        description = f"Self-service top up of ${Decimal(amount).quantize(TWO_PLACES)}"

        # Top-up balance.
        user_acc = db.session.query(Account).join(User).filter(User.id == current_user.id).first().acc_number
        error = bamc.topup_balance(current_user.id, user_acc, amount, description)

        if error is not None:
            return render_template('topup.html', title="Top Up", form=form, msg_data=msg_data, topup_error=error)

        # Send the email.
        mmc.send_top_up(Decimal(amount).quantize(TWO_PLACES), current_user)
        emc.send_email(current_user.email, "HX-Bank - Top Up",
                       render_template('/email_templates/top-up.html', amount=Decimal(amount).quantize(TWO_PLACES),
                                       time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        # Logging.
        logger = logging.getLogger('user_activity_log')
        logger.info(f"src_ip {ip_source} -> {current_user.username} has topped up {amount}")

        return redirect(url_for('views.success'))
    return render_template('topup.html', title="Top Up", form=form, msg_data=msg_data)


@views.route("/communication/compose", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def compose():
    msg_data = load_nav_messages()
    ip_source = ipaddress.IPv4Address(request.remote_addr)
    mmc = MessageManagementController()
    form = ComposeMessage()
    admins = User.query.filter_by(is_admin=True).all()
    data = []
    if not current_user.is_admin:
        for admin in admins:
            admin_data = Account.query.filter_by(userid=admin.id).first()
            acc_num = admin_data.acc_number
            admin_user_data = User.query.filter_by(id=admin.id).first()
            first_name = admin_user_data.firstname
            last_name = admin_user_data.lastname
            user_data = f"{acc_num} - {first_name} {last_name}"
            data.append(user_data)
        form.recipient.choices = data
    else:
        msgs = db.session.query(Message).filter_by(userid=current_user.id).all()
        if msgs:
            for msg in msgs:
                username = User.query.filter_by(username=msg.sender).first()
                if username is not None:
                    acc_num = Account.query.filter_by(userid=username.id).first().acc_number
                    first_name = username.firstname
                    last_name = username.lastname
                    user_data = f"{acc_num} - {first_name} {last_name}"
                    if user_data not in data:
                        data.append(user_data)
        form.recipient.choices = data

    if request.method == 'POST' and form.validate_on_submit():
        acc_number = escape(form.recipient.data.split(" ")[0])
        userid = Account.query.filter_by(acc_number=acc_number).first().userid
        if userid:
            target_user = User.query.filter_by(id=userid).first()
            if current_user.id == userid:
                error = "An error has occurred"
                return render_template('compose.html', msg_data=msg_data, form=form, compose_error=error)
            error = "Message Sent!"
            user = User.query.filter_by(id=userid).first()
            if not current_user.is_admin and not target_user.is_admin:
                error = "Something went wrong"
                return render_template('compose.html', msg_data=msg_data, form=form, compose_error=error)

            mmc.user_created_message(escape(form.message.data), current_user.username, user)

            # Logging.
            logger = logging.getLogger('user_activity_log')
            logger.info(f"src_ip {ip_source} -> {current_user.username} has sent a message to {user.username}")

            return render_template('compose.html', msg_data=msg_data, form=form, compose_error=error)
        else:
            error = "Something went wrong"
            return render_template('compose.html', msg_data=msg_data, form=form, compose_error=error)
    return render_template('compose.html', msg_data=msg_data, form=form)


@views.route("/communication/message-center", methods=['GET', 'POST'])
@login_required
# @check_email_verification
def message_center():
    # Initiate the controller.
    mmc = MessageManagementController()

    # Load the messages.
    msg_data = load_nav_messages()

    # Initiate the message form.
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
            # Mark message.
            if form.data["mark"]:
                mmc.mark_message(msg)

            # Unmark message.
            elif form.data["unmark"]:
                mmc.unmark_message(msg)

            # Delete message.
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
# @check_email_verification
def transaction_management():
    if not current_user.is_admin:
        return redirect(url_for('views.dashboard'))
    form = ApproveTransactionForm()

    # Check that the form was submitted.
    if request.method == "POST" and form.validate_on_submit():
        # Get the transaction id.
        transaction = Transaction.query.filter_by(id=escape(form.transactionid.data)).first()

        # Get the transferrer's account information.
        transferrer_acc = Account.query.filter_by(acc_number=transaction.transferrer_acc_number).first()

        # Update the balance for both transferrer and transferee if approved.
        if escape(form.approve.data):
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
    # Initiate the controller.
    amc = AccountManagementController()

    #
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

                # Change password.
                password = flask_bcrypt.generate_password_hash(form.password.data)
                amc.change_pw(user, password)

                # Send reset password link.
                emc.send_email(current_user.email, "HX-Bank - Password Change",
                               render_template('/email_templates/reset.html', reset="password",
                                               time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                mmc.send_password_change(user)

                # Logging.
                logger = logging.getLogger('user_activity_log')
                logger.info(f"src_ip {ip_source} -> {current_user.username} has changed their password")

                return redirect(url_for("views.acc_settings"))
            else:
                error = "Incorrect OTP"
                return render_template('change-pwd.html', form=form, reset_error=error, msg_data=msg_data)
    return render_template('change-pwd.html', form=form, msg_data=msg_data)


@views.route('/account-management/change-otp', methods=['GET', 'POST'])
@login_required
# @check_email_verification
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
    mmc = MessageManagementController()
    emc = EmailManagementController()
    if current_user.prev_token is not None:
        emc.send_email(current_user.email, "HX-Bank - OTP Reset",
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
    r.headers['X-Content-Type-Options'] = 'nosniff'
    return r
