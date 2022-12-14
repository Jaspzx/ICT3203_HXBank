import os
import socket
from flask import Flask, render_template
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from flask_talisman import Talisman
from logging.config import dictConfig
from .flask_simple_crypt import SimpleCrypt
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy()
flask_bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
mail = Mail()
talisman = Talisman()
encryptor = SimpleCrypt()

from webportal.models.User import *
from webportal.models.Account import *
from webportal.models.Transaction import *
from webportal.models.Transferee import *
from webportal.models.Message import *
from dotenv import load_dotenv

FORMAT = "%(asctime)s {app} [%(thread)d] %(levelname)-5s %(name)s - %(message)s."
formatted = FORMAT.format(app=__name__)
log_dir = os.path.join(os.getcwd(), "webportal", "log")
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


def create_webportal() -> Flask:
    load_dotenv()
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
    app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv('PERMANENT_SESSION_LIFETIME')))
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
    app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
    app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
    app.config['RECAPTCHA_DATA_ATTRS'] = {'bind': 'recaptcha-submit', 'callback': 'onSubmitCallback',
                                          'size': 'invisible'}
    app.config['FSC_EXPANSION_COUNT'] = 2048
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    db.init_app(app)
    encryptor.init_app(app)
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
            ],
            'object-src': '\'self\'',
        },
        content_security_policy_nonce_in=['script-src', 'style-src'],
        session_cookie_samesite="Lax"
    )
    login_manager.session_protection = "strong"
    login_manager.login_view = 'views.login'

    with app.app_context():
        db.create_all()
        try:
            username = "super_user"
            firstname = encryptor.encrypt(os.getenv('SUPER_USER_FIRSTNAME'))
            lastname = encryptor.encrypt(os.getenv('SUPER_USER_LASTNAME'))
            address = encryptor.encrypt("None")
            email = encryptor.encrypt(os.getenv('SUPER_USER_EMAIL'))
            nric = encryptor.encrypt(os.getenv('SUPER_USER_NRIC'))
            mobile = encryptor.encrypt(os.getenv('SUPER_USER_MOBILE'))
            dob = encryptor.encrypt(os.getenv('SUPER_USER_DOB'))
            password = flask_bcrypt.generate_password_hash(os.getenv('SUPER_USER_PASSWORD'))
            user = User(username, firstname, lastname, address, email, mobile, nric, dob, password, None, None, True)
            db.session.add(user)
            db.session.commit()
            db.session.close()
        except:
            pass

    from .views import views
    app.register_blueprint(views, url_prefix='/')

    def page_not_found(e):
        return render_template('404.html'), 404

    app.register_error_handler(404, page_not_found)

    def internal_server_error(e):
        return render_template('500.html'), 500

    app.register_error_handler(500, internal_server_error)

    return app


def create_test_webportal() -> Flask:
    load_dotenv()
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
    app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv('PERMANENT_SESSION_LIFETIME')))
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
    app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
    app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
    app.config['RECAPTCHA_DATA_ATTRS'] = {'bind': 'recaptcha-submit', 'callback': 'onSubmitCallback',
                                          'size': 'invisible'}
    app.config['FSC_EXPANSION_COUNT'] = 2048
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.config['TESTING'] = True
    app.config['DEBUG'] = True
    app.config["WTF_CSRF_ENABLED"] = False
    db.init_app(app)
    encryptor.init_app(app)
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
            ],
            'object-src': '\'self\'',
        },
        content_security_policy_nonce_in=['script-src', 'style-src'],
        session_cookie_samesite="Strict"
    )
    login_manager.session_protection = "strong"
    login_manager.login_view = 'views.login'

    from .views import views
    app.register_blueprint(views, url_prefix='/')

    def page_not_found(e):
        return render_template('404.html'), 404

    app.register_error_handler(404, page_not_found)

    def internal_server_error(e):
        return render_template('500.html'), 500

    app.register_error_handler(500, internal_server_error)

    return app
