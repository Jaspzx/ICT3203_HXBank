from flask_login import UserMixin
from datetime import datetime, timedelta
from webportal import db
import pyotp


class User(db.Model, UserMixin):
    id = db.Column(db.INT, primary_key=True)
    username = db.Column(db.String(50))
    firstname = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    address = db.Column(db.String(50))
    email = db.Column(db.String(150))
    mobile = db.Column(db.String(10))
    nric = db.Column(db.String(9))
    dob = db.Column(db.Date())
    password_hash = db.Column(db.String(150))
    otp_secret = db.Column(db.String(16))
    date_joined = db.Column(db.DateTime())
    failed_login_attempts = db.Column(db.INT)
    last_login = db.Column(db.DateTime(timezone=True))
    unlock_ts = db.Column(db.DateTime(timezone=True))
    email_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, username, firstname, lastname, address, email, mobile, nric, dob, password_hash, otp_secret):
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.address = address
        self.email = email
        self.mobile = mobile 
        self.nric = nric
        self.dob = dob
        self.password_hash = password_hash
        self.otp_secret = otp_secret
        if self.otp_secret is None:
            self.otp_secret = pyotp.random_base32()
        self.date_joined = datetime.now()
        self.failed_login_attempts = 0
        self.last_login = datetime.now()
        self.unlock_ts = datetime.now()

    def get_totp_uri(self):
        return f'otpauth://totp/HX-Bank:{self.username}?secret={self.otp_secret}&issuer=HX-Bank'

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token)


def createUser(username, firstname, lastname, address, email, mobile, nric, dob, password, otp_secret=None):
    new_user = User(username, firstname, lastname, address, email, mobile, nric, dob, password, otp_secret)
    try:
        db.session.add(new_user)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()


def delUser():
    pass


def reset_secret(arg_user):
    arg_user.otp_secret = pyotp.random_base32()
    try:
        db.session.commit()
    except:
        db.session.rollback()


def update_on_success(arg_user):
    arg_user.last_login = datetime.now()
    arg_user.failed_login_attempts = 0
    try:
        db.session.commit()
    except:
        db.session.rollback()


def update_on_failure(arg_user):
    arg_user.failed_login_attempts += 1
    if arg_user.failed_login_attempts > 6:
        arg_user.unlock_ts = datetime.now() + timedelta(minutes=30)
    try:
        db.session.commit()
    except:
        db.session.rollback()


def reset_details(arg_user, arg_field, arg_value):
    if arg_field == "username":
        arg_user.username = arg_value
    elif arg_field == "password":
        arg_user.password_hash = arg_value
    try:
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()
