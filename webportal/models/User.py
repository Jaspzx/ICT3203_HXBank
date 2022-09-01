from flask_login import UserMixin
from datetime import datetime 
from webportal import db

class User(db.Model, UserMixin):
    id = db.Column(db.INT, primary_key=True)
    username = db.Column(db.String(50))
    firstname = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    address = db.Column(db.String(50))
    email = db.Column(db.String(150))
    password_hash = db.Column(db.String(150))
    account_number = db.column(db.INT())
    date_joined = db.Column(db.DateTime(), default=datetime.utcnow)

def set_password(self, password):
    self.password_hash = generate_password_hash(password)

def check_password(self,password):
    return check_password_hash(self.password_hash,password)    