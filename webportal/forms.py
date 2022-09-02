from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, TextAreaField, IntegerField, BooleanField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, EqualTo, Regexp
from wtforms.widgets import PasswordInput


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=20)])
    firstname = StringField("First Name", validators=[InputRequired(), Length(min=3, max=20)])
    lastname = StringField("Last Name", validators=[InputRequired(), Length(min=3, max=20)])
    address = StringField("Address", validators=[InputRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8),
                                                     EqualTo('confirm_password', message='Passwords must match'),
                                                     Regexp("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$",
                                                            message="Password complexity not met")])
    confirm_password = PasswordField("Repeat Password")
    email = StringField("Email", validators=[InputRequired(), Length(min=3, max=50), Email()])
    accept_tos = BooleanField("I accept the Terms & Conditions", validators=[InputRequired()])


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired()],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class Token2FAForm(FlaskForm):
    token = StringField("2FA Token", validators=[InputRequired(), Length(min=6, max=6)],
                        render_kw={"placeholder": "OTP Token"})
    submit = SubmitField("Authenticate")
