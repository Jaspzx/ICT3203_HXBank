from flask_login import UserMixin
from datetime import datetime
from webportal import db
import pyotp


class User(db.Model, UserMixin):
    id = db.Column(db.INT, primary_key=True)
    username = db.Column(db.String(50))
    firstname = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    address = db.Column(db.String(50))
    email = db.Column(db.String(150))
    password_hash = db.Column(db.String(150))
    otp_secret = db.Column(db.String(16))
    date_joined = db.Column(db.DateTime())

    def __init__(self, username, firstname, lastname, address, email, password_hash, otp_secret):
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.address = address
        self.email = email
        self.password_hash = password_hash
        self.otp_secret = otp_secret
        if self.otp_secret is None:
            self.otp_secret = pyotp.random_base32()
        self.date_joined = datetime.now()

    def get_totp_uri(self):
        return f'otpauth://totp/HX-Bank:{self.username}?secret={self.otp_secret}&issuer=HX-Bank'

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token)


def createUser(username, firstname, lastname, address, email, password, otp_secret=None):
    new_user = User(username, firstname, lastname, address, email, password, otp_secret)
    try:
        db.session.add(new_user)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()


def delUser():
    pass
