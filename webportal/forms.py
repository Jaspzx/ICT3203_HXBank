from flask_wtf import FlaskForm, RecaptchaField
from flask_login import current_user
from wtforms import StringField, DateField, IntegerField, BooleanField, PasswordField, SubmitField, SelectField, \
    DecimalField, HiddenField
from wtforms.validators import InputRequired, Length, Email, EqualTo, Regexp
from webportal.models.Account import *


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=20),
                                                   Regexp("^[A-Za-z][A-Za-z0-9_]{3,20}$",
                                                          message="Invalid username")])
    firstname = StringField("First Name", validators=[InputRequired(), Length(min=3, max=20),
                                                      Regexp("^(?=.{1,40}$)[a-zA-Z]+(?:[-'\\s][a-zA-Z]+)*$",
                                                             message="Invalid name")])
    lastname = StringField("Last Name", validators=[InputRequired(), Length(min=3, max=20),
                                                    Regexp("^(?=.{1,40}$)[a-zA-Z]+(?:[-'\\s][a-zA-Z]+)*$",
                                                           message="Invalid name")])
    address = StringField("Address", validators=[InputRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8),
                                                     EqualTo('confirm_password', message='Passwords must match'),
                                                     Regexp(
                                                         "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$",
                                                         message="Password complexity not met")])
    confirm_password = PasswordField("Repeat Password")
    email = StringField("Email", validators=[InputRequired(), Length(min=5, max=50), Email()])
    nric = StringField("Identification No.", validators=[InputRequired(),
                                                         Length(min=9, max=9),
                                                         Regexp("^[STFGstfg]\\d{7}[A-Za-z]$",
                                                                message="Invalid Identification no.")])
    dob = DateField("Date of Birth", validators=[InputRequired()], format='%Y-%m-%d')
    mobile = StringField("Mobile", validators=[InputRequired(), Length(min=8, max=20),
                                               Regexp("\\d{8,}$")])
    accept_tos = BooleanField("I accept the Terms & Conditions", validators=[InputRequired()])
    submit = SubmitField("Sign Up")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=20),
                                                   Regexp("^[A-Za-z][A-Za-z0-9_]{3,20}$",
                                                          message="Invalid username")])
    password = PasswordField("Password", validators=[InputRequired()],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Sign In")


class Token2FAForm(FlaskForm):
    token = StringField("2FA Token", validators=[InputRequired(),
                                                 Length(min=6, max=6),
                                                 Regexp("^\\d{6,6}$")],
                        render_kw={"placeholder": "OTP Token"})
    submit = SubmitField("Authenticate")


class ResetFormIdentify(FlaskForm):
    nric = StringField("Identification No.", validators=[InputRequired(), Length(min=9, max=9),
                                                         Regexp("^[STFGstfg]\\d{7}[A-Za-z]$",
                                                                message="Invalid Identification no.")])
    dob = DateField("Date of Birth", validators=[InputRequired()], format='%Y-%m-%d')
    submit = SubmitField("Next")


class ResetFormAuthenticate(FlaskForm):
    token = StringField("2FA Token", validators=[InputRequired(), Length(min=6, max=6), Regexp("^\\d{6,6}$")],
                        render_kw={"placeholder": "OTP Token"})
    submit = SubmitField("Next")


class ResetPasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8),
                                                     EqualTo('confirm_password', message='Passwords must match'),
                                                     Regexp(
                                                         "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$",
                                                         message="Password complexity not met")])
    confirm_password = PasswordField("Repeat Password")
    submit = SubmitField("Reset")


class ResetUsernameForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=20),
                                                   Regexp("^[A-Za-z][A-Za-z0-9_]{3,20}$", message="Invalid username")])
    submit = SubmitField("Reset")


class AddTransfereeForm(FlaskForm):
    transferee_acc = StringField("Transferee Account No", validators=[InputRequired(), Length(min=10, max=10),
                                                                       Regexp("^\\d{10,10}$",
                                                                              message="Invalid account number")])
    submit = SubmitField("Add")


class SetTransferLimitForm(FlaskForm):
    transfer_limit = IntegerField("Set Transfer Limit", validators=[InputRequired()])
    submit = SubmitField("Set")


class TransferMoneyForm(FlaskForm):
    transferee_acc = SelectField("Transferee", coerce=str, validators=[InputRequired()])
    amount = DecimalField("Amount to Transfer.", validators=[InputRequired()])
    description = StringField("Description.", validators=[InputRequired(), Length(min=1, max=50)])
    submit = SubmitField("Transfer")


class RemoveTransfereeForm(FlaskForm):
    transferee_acc = HiddenField()
    submit = SubmitField("Remove")


class SecureMessageForm(FlaskForm):
    msg = HiddenField()
    mark = SubmitField("Read")
    unmark = SubmitField("Unread")
    delete = SubmitField("Delete")


class TopUpForm(FlaskForm):
    amount = DecimalField("Amount to Top Up", validators=[InputRequired()])
    submit = SubmitField("Top Up")

class UnlockUserForm(FlaskForm):
    userid = HiddenField()
    unlock = SubmitField("Unlock")


class ApproveTransactionForm(FlaskForm):
    transactionid = HiddenField()
    approve = SubmitField("Approve")
    reject = SubmitField("Reject")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[InputRequired()],
                             render_kw={"placeholder": "Password"})
    password = PasswordField("New Password", validators=[InputRequired(), Length(min=8),
                                                     EqualTo('confirm_password', message='Passwords must match'),
                                                     Regexp(
                                                         "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$",
                                                         message="Password complexity not met")])
    confirm_password = PasswordField("Repeat Password")
    submit = SubmitField("Reset")
