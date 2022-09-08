from io import BytesIO
import pyqrcode
from flask import Blueprint, redirect, url_for, render_template, request, session, abort
from flask_login import login_required, login_user, logout_user
from webportal import flask_bcrypt, login_manager
from webportal.models.Transferee import *
from .forms import *
from .utils.messaging import *

views = Blueprint('views', __name__)


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
        createUser(username, firstname, lastname, address, email, mobile, nric, dob, password)
        user = User.query.filter_by(username=username).first()
        createAccount(user.id)
        session['username'] = username
        return redirect(url_for("views.otp_setup"))
    return render_template('register.html', title="Register", form=form)


@views.route('/otp-setup')
def otp_setup():
    if 'username' not in session:
        return render_template('home.html', title="Home Page")
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return render_template('home.html', title="Home Page")
    return render_template('otp-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@views.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    if not current_user.is_authenticated:
        user = User.query.filter_by(username=session['username']).first()
        if user is None:
            abort(404)
        del session['username']
        url = pyqrcode.create(user.get_totp_uri())
        stream = BytesIO()
        url.svg(stream, scale=3)
        return stream.getvalue(), 200, {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}
    elif current_user.is_authenticated:
        user = User.query.filter_by(username=current_user.id).first()
        if user is None:
            abort(404)
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
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('views.admin_dashboard'))
        return redirect(url_for('views.dashboard'))
    if 'type' in session:
        del session['type']
    form = LoginForm()
    error = "Login Failed"
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if flask_bcrypt.check_password_hash(user.password_hash, form.password.data):
                if datetime.now() < user.unlock_ts:
                    error = "Account has been locked out, try again later"
                    return render_template('login.html', title="Login", form=form, login_error=error)
                session['username'] = user.username
                return redirect(url_for('views.otp_input'))
            else:
                update_on_failure(user)
                return render_template('login.html', title="Login", form=form, login_error=error)
        else:
            return render_template('login.html', title="Login", form=form, login_error=error)
    return render_template('login.html', title="Login", form=form)


@views.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('views.login'))


@views.route('/otp-input', methods=['GET', 'POST'])
def otp_input():
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
        if user and user.verify_totp(form.token.data):
            del session['username']
            login_user(user)
            if current_user.failed_login_attempts > 0:
                message_add(f"There were {current_user.failed_login_attempts} failed login attempt(s) between your "
                            f"current and last session", current_user.id)
            message_add(f"You have logged in on {current_user.last_login}", current_user.id)
            update_on_success(user)
            if current_user.is_admin is True:
                return redirect(url_for('views.admin_dashboard'))
            return redirect(url_for('views.dashboard'))
        else:
            return render_template('otp-input.html', form=form, login_error=error)
    return render_template('otp-input.html', form=form)


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
                user_username = User.query.filter_by(username=session['username']).first()
                if user_username.nric == session['nric'] and user_username.dob == session['dob']:
                    del session['nric']
                    del session['dob']
                    return redirect(url_for("views.otp_setup"))
                else:
                    del session['nric']
                    del session['username']
                    del session['dob']
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
        if user and user.verify_totp(form.token.data):
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
            reset_details(user, "password", password)
            return redirect(url_for("views.login"))
        else:
            return render_template('reset-pwd.html', form=form, reset_error=error)
    return render_template('reset-pwd.html', form=form)


@views.route('/reset-username', methods=['GET', 'POST'])
def reset_username():
    if 'nric' not in session:
        return redirect(url_for('views.reset_identity'))
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
                reset_details(user, "username", form.username.data)
            return redirect(url_for("views.login"))
        else:
            return render_template('reset-username.html', form=form, reset_error=error)
    return render_template('reset-username.html', form=form)


@views.route('/personal-banking/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    msg_data = load_nav_messages()
    if current_user.is_admin:
        return render_template('admin-dashboard.html', title="Admin Dashboard", data=data, msg_data=msg_data)
    return render_template('dashboard.html', title="Dashboard", data=data, msg_data=msg_data)


@views.route("/personal-banking/profile", methods=['GET', 'POST'])
@login_required
def profile():
    msg_data = load_nav_messages()
    return render_template('profile.html', title="Profile Page", msg_data=msg_data)


@views.route("/personal-banking/admin-dashboard", methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    data = db.session.query(Account).join(User).filter(User.id == current_user.id).first()
    msg_data = load_nav_messages()
    if not current_user.is_admin:
        return render_template('dashboard.html', title="Dashboard", data=data, msg_data=msg_data)
    return render_template('admin-dashboard.html', title="Admin Dashboard", data=data, msg_data=msg_data)


@views.route("/personal-banking/transfer", methods=['GET', 'POST'])
@login_required
def transfer():
    msg_data = load_nav_messages()
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
        # Amount to debit and credit from transferee and transferrer respectively.
        amount = form.amount.data
        if amount <= 0:
            error = "Invalid amount"
            return render_template('transfer.html', title="Transfer", form=form, msg_data=msg_data, xfer_error=error)

        # Get the transferee's account information. 
        transferee_acc_number = form.transferee_acc.data.split(" ")[0]
        transferee_userid = Account.query.filter_by(acc_number=transferee_acc_number).first().userid

        # Check that the amount to be transferred does not exceed the transfer limit.
        day_amount = transferrer_acc.acc_xfer_daily + amount

        if datetime.now().date() < transferrer_acc.reset_xfer_limit_date.date() and day_amount > transferrer_acc.acc_xfer_limit:
            error = "Amount to be transferred exceeds daily transfer limit"
            return render_template('transfer.html', title="Transfer", form=form, xfer_error=error, msg_data=msg_data)
        if transferrer_acc.acc_balance < amount:
            error = "Insufficient funds"
            return render_template('transfer.html', title="Transfer", form=form, xfer_error=error, msg_data=msg_data)

        # Create a transaction history.
        require_approval = False
        if amount > 10000:
            require_approval = True
        updateBalance(transferrer_userid, transferee_userid, amount)
        transferer_acc_number = Account.query.filter_by(userid=transferrer_userid).first().acc_number
        message_add(f"You have requested a transfer of ${amount} to {form.transferee_acc.data}.", transferrer_userid)
        createTransaction(amount, transferer_acc_number, transferee_acc_number, require_approval)

        # Return success page.
        return redirect(url_for('views.success'))

    # Render the HTML template.
    return render_template('transfer.html', title="Transfer", form=form, msg_data=msg_data, balance=transferrer_acc.acc_balance)


@views.route("/personal-banking/add-transferee", methods=['GET', 'POST'])
@login_required
def add_transferee():
    msg_data = load_nav_messages()
    form = AddTransfereeForm()
    if request.method == 'POST' and form.validate_on_submit():
        # Get the transferee info based on the account number provided by the user.
        transferee_acc = Account.query.filter_by(acc_number=form.transferee_acc.data).first()

        print(transferee_acc)
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
                message_add(f"You have added account number:{transferee_acc.acc_number}, as a transfer recipient",
                            current_user.id)
                transferee_add(current_user.id, transferee_acc.userid)
                return redirect(url_for('views.success'))

        # Return error if the transferee info does not exist based on the account number provided by the user.
        else:
            add_error = "Invalid account!"
            return render_template('add-transferee.html', title="Add Transferee", form=form, add_error=add_error,
                                   msg_data=msg_data)

    return render_template('add-transferee.html', title="Add Transferee", form=form, msg_data=msg_data)


@views.route("/personal-banking/transaction-history", methods=['GET', 'POST'])
@login_required
def transaction_history():
    msg_data = load_nav_messages()
    # Get the list of transactions that the user is involved in.
    user_acc_number = Account.query.filter_by(userid=current_user.id).first().acc_number
    transfer_data = Transaction.query.filter_by(transferrer_acc_number=user_acc_number).all()
    transferee_data = Transaction.query.filter_by(transferee_acc_number=user_acc_number).all()
    data = []

    # Combine the transactions together.
    for item in transfer_data:
        data.append({"date_transferred": item.date_transferred, "amt_transferred": item.amt_transferred,
                     "transferrer_acc": item.transferrer_acc_number, "transferee_acc": item.transferee_acc_number,
                     "require_approval": item.require_approval, "debit": False})
    for item in transferee_data:
        data.append({"date_transferred": item.date_transferred, "amt_transferred": item.amt_transferred,
                     "transferrer_acc": item.transferrer_acc_number, "transferee_acc": item.transferee_acc_number,
                     "require_approval": item.require_approval, "debit": True})

    # Sort by latest date first.
    data.sort(key=lambda r: r["date_transferred"], reverse=True)
    data = {x['date_transferred']: x for x in data}.values()

    # Render template.
    return render_template('transaction-history.html', title="Transaction History", data=data, msg_data=msg_data)


@views.route("/personal-banking/view-transferee", methods=['GET', 'POST'])
@login_required
def view_transferee():
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
        transferee_remove(current_user.id, transferee_id)
        return redirect(url_for('views.success'))
    return render_template('view-transferee.html', title="View Transferee", data=data, form=form, msg_data=msg_data)


@views.route("/personal-banking/set-transfer-limit", methods=['GET', 'POST'])
@login_required
def set_transfer_limit():
    msg_data = load_nav_messages()
    # Init the SetTransferLimitForm.
    form = SetTransferLimitForm()
    if request.method == 'POST' and form.validate_on_submit():
        setTransferLimit(current_user.id, form.transfer_limit.data)
        return redirect(url_for('views.success'))
    return render_template('set-transfer-limit.html', title="Set Transfer Limit", form=form, msg_data=msg_data)


@views.route("/personal-banking/topup-balance", methods=['GET', 'POST'])
@login_required
def topup_balance():
    msg_data = load_nav_messages()
    form = TopUpForm()
    if request.method == 'POST' and form.validate_on_submit():
        user_acc = db.session.query(Account).join(User).filter(User.id == current_user.id).first().acc_number
        message_add(f"You have made a request to top up ${form.amount.data}", current_user.id)
        topup(current_user.id, form.amount.data)
        createTransaction(form.amount.data, user_acc, user_acc, False)
        return redirect(url_for('views.success'))
    return render_template('topup.html', title="Top Up", form=form, msg_data=msg_data)


@views.route("/personal-banking/message_center", methods=['GET', 'POST'])
@login_required
def message_center():
    msg_data = load_nav_messages()
    form = SecureMessageForm()
    if request.method == 'POST' and form.validate_on_submit():
        msg = db.session.query(Message).filter_by(id=form.msg.data).first()
        if msg:
            check = db.session.query(Message).join(User).filter(msg.userid == current_user.id).first()
        else:
            error = "Something went wrong"
            return render_template('message_center.html', title="Secure Message Center", msg_data=msg_data, form=form,
                                   msg_error=error)
        if check:
            if form.data["mark"]:
                message_status(msg, True)
            elif form.data["unmark"]:
                message_status(msg, False)
            elif form.data["delete"]:
                message_del(msg)
        else:
            error = "Something went wrong"
            return render_template('message_center.html', title="Secure Message Center", msg_data=msg_data, form=form,
                                   msg_error=error)
        return redirect(url_for('views.message_center'))
    return render_template('message_center.html', title="Secure Message Center", msg_data=msg_data, form=form)


@views.route("/success")
@login_required
def success():
    return render_template('success.html', title="Success")


@views.route("/robots.txt")
def robots():
    return render_template('robots.txt', title="Robots")


@views.before_request
def make_session_permanent():
    session.permanent = True


@views.after_request
def add_header(r):
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r
