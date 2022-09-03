from datetime import datetime
import pyqrcode
from flask import Flask, Blueprint, redirect, url_for, render_template, request, session, abort
from flask_login import login_required, login_user, logout_user, current_user
from .forms import RegisterForm, LoginForm, Token2FAForm
from webportal.models.User import *
from webportal import flask_bcrypt, login_manager
from io import BytesIO

views = Blueprint('views', __name__)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@views.route('/')
def home():
    return render_template('home.html', title="Home Page")


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
        password = flask_bcrypt.generate_password_hash(form.password.data)
        createUser(username, firstname, lastname, address, email, mobile, nric, password)
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
    return redirect(url_for('views.login'))


@views.route('/otp_input', methods=('GET', 'POST'))
def otp_input():
    form = Token2FAForm(request.form)
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
    return render_template('otp_input.html', form=form)


@views.route('/dashboard', methods=('GET', 'POST'))
@login_required
def dashboard():
    return render_template('dashboard.html', title="Dashboard",
                           name=f"{current_user.firstname} {current_user.lastname}!")

@views.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if current_user.is_admin:
        return render_template('admin-dashboard.html', title="Admin Dashboard")
    return redirect(url_for('views.dashboard'))


@views.route("/robots.txt")
def robots():
    return render_template('robots.txt', title="Robots")
