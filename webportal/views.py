import pyqrcode
from flask import Flask, Blueprint, redirect, url_for, render_template, request, session, abort
from flask_login import login_required, login_user, logout_user, current_user
from .forms import *
from webportal.models.User import *
from webportal.models.Account import *
from webportal.models.Transaction import * 
from webportal import flask_bcrypt, login_manager
from io import BytesIO

views = Blueprint('views', __name__)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@views.route('/')
def home():
    return render_template('home.html', title="Home Page")


@views.route('/about')
def about():
    return render_template('about.html', title="About")


@views.route('/register', methods=('GET', 'POST'))
def register():
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            return render_template('register.html', title="Register", form=form, register_error="Username exists")
        username = form.username.data
        firstname = form.firstname.data
        lastname = form.lastname.data
        address = form.address.data
        email = form.email.data
        mobile = form.mobile.data
        nric = form.nric.data
        dob = form.dob.data
        password = flask_bcrypt.generate_password_hash(form.password.data)
        user = createUser(username, firstname, lastname, address, email, mobile, nric, dob, password)
        user = User.query.filter_by(username=username).first()
        createAccount(user.id)
        session['username'] = username
        return redirect(url_for("views.otp_setup"))
    return render_template('register.html', title="Register", form=form)


@views.route('/otp_setup')
def otp_setup():
    if 'username' not in session:
        return render_template('home.html', title="Home Page")
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return render_template('home.html', title="Home Page")
    return render_template('otp_setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@views.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
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


@views.route('/login', methods=('GET', 'POST'))
def login():
    if current_user.is_authenticated:
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


@views.route('/logout', methods=('GET', 'POST'))
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('views.login'))


@views.route('/otp_input', methods=('GET', 'POST'))
def otp_input():
    form = Token2FAForm(request.form)
    error = "Invalid Token"
    if 'username' not in session:
        return redirect(url_for('views.login'))
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('views.admin-dashboard'))
        return redirect(url_for('views.dashboard'))
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=session['username']).first()
        if user and user.verify_totp(form.token.data):
            del session['username']
            login_user(user, duration=timedelta(minutes=5))
            update_on_success(user)
            if current_user.is_admin is True:
                return redirect(url_for('views.admin_dashboard'))
            return redirect(url_for('views.dashboard'))
        else:
            return render_template('otp_input.html', form=form, login_error=error)
    return render_template('otp_input.html', form=form)


@views.route('/reset_identify', methods=('GET', 'POST'))
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
        user = User.query.filter_by(nric=form.nric.data).first()
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
                    return render_template('reset_identify.html', form=form, identity_error=error)
        else:
            return render_template('reset_identify.html', form=form, identity_error=error)
    return render_template('reset_identify.html', form=form)


@views.route('/reset_authenticate', methods=('GET', 'POST'))
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
            return render_template('reset_authenticate.html', form=form, authenticate_error=error)
    return render_template('reset_authenticate.html', form=form)


@views.route('/reset_pwd', methods=('GET', 'POST'))
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
            return render_template('reset_pwd.html', form=form, reset_error=error)
    return render_template('reset_pwd.html', form=form)


@views.route('/reset_username', methods=('GET', 'POST'))
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
                return render_template('reset_username.html', form=form, reset_error="Username exists")
            else:
                del session['nric']
                reset_details(user, "username", form.username.data)
            return redirect(url_for("views.login"))
        else:
            return render_template('reset_username.html', form=form, reset_error=error)
    return render_template('reset_username.html', form=form)


@views.route('/dashboard', methods=('GET', 'POST'))
@login_required
def dashboard():
    data = db.session.query(Account).filter(User.id == current_user.id ).first()
    return render_template('dashboard.html', title="Dashboard",
                           name=f"{current_user.firstname} {current_user.lastname}!", data=data)


@views.route("/profile")
@login_required
def profile():
    return render_template('profile.html', title="Profile Page")


@views.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if current_user.is_admin:
        return render_template('admin-dashboard.html', title="Admin Dashboard")
    return redirect(url_for('views.dashboard'))


@views.route("/add-transferee")
@login_required
def add_transferee():
    return render_template('add-transferee.html', title="Add Transferee")
   

@views.route("/transaction-history")
@login_required
def transaction_history():
    return render_template('transaction-history.html', title="Transaction History")


@views.route("/robots.txt")
def robots():
    return render_template('robots.txt', title="Robots")
