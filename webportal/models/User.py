from flask_login import UserMixin
from datetime import datetime
from webportal import db
import pyotp


class User(db.Model, UserMixin):
    id = db.Column(db.INT, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    firstname = db.Column(db.String(200), nullable=False)
    lastname = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    mobile = db.Column(db.String(200), nullable=False)
    nric = db.Column(db.String(200), unique=True, nullable=False)
    dob = db.Column(db.String(200), nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    otp_secret = db.Column(db.String(40), nullable=False)
    prev_token = db.Column(db.String(6))
    date_joined = db.Column(db.DateTime(), nullable=False)
    failed_login_attempts = db.Column(db.INT, nullable=False)
    last_login = db.Column(db.DateTime(timezone=True))
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_token = db.Column(db.String(150))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_disabled = db.Column(db.Boolean, default=False, nullable=False)
    session_token = db.Column(db.String(40), index=True)

    def __init__(self, username, firstname, lastname, address, email, mobile, nric, dob, password_hash, otp_secret,
                 token, is_admin):
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
        self.prev_token = None
        self.date_joined = datetime.now()
        self.failed_login_attempts = 0
        self.last_login = datetime.now()
        self.email_token = token
        self.is_disabled = False
        self.is_admin = is_admin

    def get_totp_uri(self):
        return f'otpauth://totp/HX-Bank:{self.username}?secret={self.otp_secret}&issuer=HX-Bank'

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token)

    def get_id(self):
        return str(self.session_token)
