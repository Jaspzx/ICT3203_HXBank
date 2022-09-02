from datetime import timedelta
from flask import Blueprint, redirect, url_for
from flask import Flask, render_template
from flask_login import login_required, login_user, logout_user, current_user
from .forms import RegisterForm, LoginForm
from webportal.models.User import *
from webportal import flask_bcrypt, login_manager

views = Blueprint('views', __name__)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@views.route('/')
def home():
	return render_template('home.html', title="Home Page")


@views.route('/register', methods=('GET', 'POST'))
def register(): 
	form = RegisterForm()
	if form.validate_on_submit():
		username = form.username.data
		firstname = form.firstname.data
		lastname = form.lastname.data
		address = form.address.data
		email = form.email.data
		password = flask_bcrypt.generate_password_hash(form.password.data)
		createUser(username, firstname, lastname, address, email, password)       
		return redirect(url_for("views.registration_successful"))
	return render_template('register.html', title="Register", form=form)


@views.route("/registration_successful")
def registration_successful():
	return render_template('registration_successful.html', title="Registration Successful") 


@views.route('/login', methods=('GET', 'POST'))
def login():
    form = LoginForm()
    error = "Login Failed"
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if flask_bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user, duration=timedelta(minutes=5))
                return redirect(url_for('views.dashboard'))
            else:
                return render_template('login.html', title="Login", form=form, login_error=error)
        else:
            return render_template('login.html', title="Login", form=form, login_error=error)
    return render_template('login.html', title="Login", form=form)


@views.route('/logout', methods=('GET', 'POST'))
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.login'))


@views.route('/dashboard', methods=('GET', 'POST'))
@login_required
def dashboard():
    return render_template('dashboard.html', title="Dashboard", name=f"{current_user.firstname} {current_user.lastname}!")


@views.route("/robots.txt")
def robots():
    return render_template('robots.txt', title="Robots")
