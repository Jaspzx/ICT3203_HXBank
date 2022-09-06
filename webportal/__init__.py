import secrets
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
db = SQLAlchemy()
flask_bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
DB_NAME = "database.db"

from webportal.models.User import *
from webportal.models.Account import *
from webportal.models.Transaction import *
from webportal.models.Transferee import *
from webportal.models.Message import *


def create_webportal():
    app.config['SECRET_KEY'] = secrets.token_hex(16)
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_NAME}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
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
