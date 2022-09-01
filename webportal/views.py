from flask import Blueprint
from flask import Flask, render_template
from .forms import RegisterForm

views = Blueprint('views', __name__)

@views.route('/')
def home():
    return render_template('home.html', title="Home Page")

@views.route('/register')
def register(): 
    form = RegisterForm()
    return render_template('register.html', title="Register", form=form)

@views.route('/register_status', methods=('GET', 'POST'))
def register_status():
    

    return render_template('register_status', title="Register Status")

@views.route("/robots.txt")
def robots():
    return render_template('robots.txt', title="Robots")