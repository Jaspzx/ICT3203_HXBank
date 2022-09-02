from flask import Blueprint
from flask import Flask, render_template, redirect, url_for
from .forms import RegisterForm
from webportal.models.user import *

views = Blueprint('views', __name__)

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
		password = form.password.data
		createUser(username, firstname, lastname, address, email, password)       
		return redirect(url_for("views.registration_successful"))
	return render_template('register.html', title="Register", form=form)

@views.route("/registration_successful")
def registration_successful():
	return render_template('registration_successful.html', title="Registration Successful") 

@views.route("/robots.txt")
def robots():
	return render_template('robots.txt', title="Robots")