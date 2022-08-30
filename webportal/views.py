from flask import Blueprint
from flask import Flask, render_template


views = Blueprint('views', __name__)

@views.route('/')
def home():
    return render_template('home.html', title="Home Page")


@views.route("/robots.txt")
def robots():
    return render_template('robots.txt', title="Robots")