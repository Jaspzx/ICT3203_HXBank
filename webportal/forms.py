from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, TextAreaField, IntegerField, BooleanField, PasswordField
from wtforms.validators import InputRequired, Length, Email, EqualTo
from wtforms.widgets import PasswordInput

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=20)])
    firstname = StringField("First Name", validators=[InputRequired(), Length(min=3, max=20)]) 
    lastname = StringField("Last Name", validators=[InputRequired(), Length(min=3, max=20)])
    address = StringField("Address", validators=[InputRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8), EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField("Repeat Password")
    email = StringField("Email", validators=[InputRequired(), Length(min=3, max=20), Email()])
    accept_tos = BooleanField("I accept the Terms & Conditions", validators=[InputRequired()])

