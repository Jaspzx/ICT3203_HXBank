from flask_wtf import FlaskForm
from wtforms import (StringField, TextAreaField, IntegerField, BooleanField, RadioField, SubmitField, PasswordField)
from wtforms.validators import InputRequired, Length


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    firstname = StringField("First Name", validators=[InputRequired(), Length(min=4, max=20)],
                            render_kw={"placeholder": "First Name"})
    lastname = StringField("Last Name", validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Last Name"})
    address = StringField("Address", validators=[InputRequired(), Length(min=4, max=20)],
                          render_kw={"placeholder": "Address"})
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    email = StringField("Email", validators=[InputRequired(), Length(min=4, max=20)],
                        render_kw={"placeholder": "Email"})
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")
