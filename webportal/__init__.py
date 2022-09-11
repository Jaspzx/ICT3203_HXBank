from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
import os

app = Flask(__name__)
db = SQLAlchemy()
flask_bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
mail = Mail()
DB_NAME = "database.db"

from webportal.models.User import *
from webportal.models.Account import *
from webportal.models.Transaction import *
from webportal.models.Transferee import *
from webportal.models.Message import *
from dotenv import load_dotenv


def create_webportal():
    # Without .env file
    # app.config['SECRET_KEY'] = "thisisasecretkey"
    # app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_NAME}"
    # app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # app.config['SECURITY_PASSWORD_SALT'] = "test"
    # app.config['SESSION_COOKIE_SECURE'] = True
    # app.config['MAIL_SERVER'] = ''
    # app.config['MAIL_PORT'] = 587
    # app.config['MAIL_USERNAME'] = ''
    # app.config['MAIL_PASSWORD'] = ''
    # app.config['MAIL_DEFAULT_SENDER'] = ''
    # app.config['MAIL_USE_TLS'] = True
    # Get environment variables from the env file
    # app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=600)
    # With .env file
    load_dotenv()
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv('PERMANENT_SESSION_LIFETIME')))
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
    app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE')
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')

    db.init_app(app)
    mail.init_app(app)
    flask_bcrypt.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    login_manager.login_view = 'views.login'
    with app.app_context():
        db.create_all()
    from .views import views
    app.register_blueprint(views, url_prefix='/')

    return app
