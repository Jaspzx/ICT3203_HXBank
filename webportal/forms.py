from flask_wtf import FlaskForm
from wtforms import (StringField, TextAreaField, IntegerField, BooleanField, RadioField)
from wtforms.validators import InputRequired, Length

class RegisterForm(FlaskForm):
    username = StringField('Username')
    firstname = StringField('First Name') 
    lastname = StringField("Last Name")
    address = StringField("Address")
    password = StringField("Password")
    email = StringField("Email")
    