from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from flask_talisman import Talisman
from logging.config import dictConfig
import os
import socket

app = Flask(__name__)
db = SQLAlchemy()
flask_bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
mail = Mail()
talisman = Talisman()
DB_NAME = "database.db"

from webportal.models.User import *
from webportal.models.Account import *
from webportal.models.Transaction import *
from webportal.models.Transferee import *
from webportal.models.Message import *
from dotenv import load_dotenv

# LOGGING
FORMAT = "%(asctime)s {app} [%(thread)d] %(levelname)-5s %(name)s - %(message)s."
formatted = FORMAT.format(app=__name__)
log_dir = f'{os.getcwd()}\\webportal\\log'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

LOGGING_CONFIG = {
    "version": 1,
    'disable_existing_loggers': False,
    "formatters": {
        'standard': {
            'format': formatted
        }
    },

    "handlers": {
        'default': {
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
            'level': "INFO",
            'stream': 'ext://sys.stdout'
        },
        'auth': {
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'when': 'midnight',
            'utc': True,
            'backupCount': 1,
            'level': "INFO",
            'filename': '{}/auth.log'.format(log_dir),
            'formatter': 'standard',
        },
        'user_activity': {
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'when': 'midnight',
            'utc': True,
            'backupCount': 1,
            'level': "INFO",
            'filename': '{}/transaction.log'.format(log_dir),
            'formatter': 'standard',
        }
    },

    "loggers": {
        "": {
            'handlers': ['default'],
            'level': "INFO"
        },
        "auth_log": {
            'handlers': ['auth'],
            'level': "INFO"
        },
        "user_activity_log": {
            'handlers': ['user_activity'],
            'level': "INFO"
        }
    }
}

dictConfig(LOGGING_CONFIG)
app = Flask(__name__)


def create_webportal():
    load_dotenv()
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
    app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv('PERMANENT_SESSION_LIFETIME')))
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE')
    app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE')
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
    app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
    app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
    app.config['RECAPTCHA_DATA_ATTRS'] = {'bind': 'recaptcha-submit', 'callback': 'onSubmitCallback', 'size': 'invisible'}

    db.init_app(app)
    mail.init_app(app)
    flask_bcrypt.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    talisman.init_app(
        app,
        content_security_policy={
            'default-src': '\'self\'',
            'style-src': '\'self\'',
            'script-src': [
                '\'self\'',
                'https://www.google.com/recaptcha/',
                'https://www.gstatic.com/recaptcha/'
            ],
            'img-src': [
                '\'self\'',
                'data:'
            ],
            'frame-src': [
                '\'self\'',
                'https://www.google.com/recaptcha/',
                'https://www.gstatic.com/recaptcha/'
            ]
        },
        content_security_policy_nonce_in=['script-src', 'style-src']
    )
    login_manager.session_protection = "strong"
    login_manager.login_view = 'views.login'
    with app.app_context():
        db.create_all()
    from .views import views
    app.register_blueprint(views, url_prefix='/')

    return app
