from flask_wtf import FlaskForm, RecaptchaField
from flask_login import current_user
from wtforms import StringField, DateField, IntegerField, BooleanField, PasswordField, SubmitField, SelectField, \
    FloatField, HiddenField
from wtforms.validators import InputRequired, Length, Email, EqualTo, Regexp
from webportal.models.Account import Account
passExp = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
nameExp = "^(?=.{1,40}$)[a-zA-Z]+(?:[-'\\s][a-zA-Z]+)*$"
usernameExp = "^[A-Za-z][A-Za-z0-9_]{3,20}$"
twoFaExp = "^\\d{6,6}$"

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=20),
                                                   Regexp(usernameExp,
                                                          message="Invalid username")])
    firstname = StringField("First Name", validators=[InputRequired(), Length(min=3, max=20),
                                                      Regexp(nameExp,
                                                             message="Invalid name")])
    lastname = StringField("Last Name", validators=[InputRequired(), Length(min=3, max=20),
                                                    Regexp(nameExp,
                                                           message="Invalid name")])
    address = StringField("Address", validators=[InputRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8),
                                                     EqualTo('confirm_password', message='Passwords must match'),
                                                     Regexp(
                                                        passExp,
                                                         message="Password complexity not met")])
    confirm_password = PasswordField("Confirm Password")
    email = StringField("Email", validators=[InputRequired(), Length(min=5, max=50), Email()])
    nric = StringField("Identification No.", validators=[InputRequired(),
                                                         Length(min=9, max=9),
                                                         Regexp("^[STFGstfg]\\d{7}[A-Za-z]$",
                                                                message="Invalid Identification no.")])
    dob = DateField("Date of Birth", validators=[InputRequired()], format='%Y-%m-%d')
    mobile = StringField("Mobile", validators=[InputRequired(), Length(min=8, max=20),
                                               Regexp("\\d{8,}$", message="Invalid mobile")])
    accept_tos = BooleanField("I accept the Terms & Conditions", validators=[InputRequired()])
    recaptcha = RecaptchaField()
    register_submit = SubmitField("Sign Up")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=20),
                                                   Regexp(usernameExp,
                                                          message="Invalid username")])
    password = PasswordField("Password", validators=[InputRequired()],
                             render_kw={"placeholder": "Password"})
    recaptcha = RecaptchaField()
    login_submit = SubmitField("Sign In")


class Token2FAForm(FlaskForm):
    token = StringField("2FA Token", validators=[InputRequired(),
                                                 Length(min=6, max=6),
                                                 Regexp(twoFaExp)],
                        render_kw={"placeholder": "OTP Token"})
    recaptcha = RecaptchaField()
    otp_submit = SubmitField("Authenticate")


class ResetFormIdentify(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=20),
                                                   Regexp(usernameExp,
                                                          message="Invalid username")])
    nric = StringField("Identification No.", validators=[InputRequired(), Length(min=9, max=9),
                                                         Regexp("^[STFGstfg]\\d{7}[A-Za-z]$",
                                                                message="Invalid Identification no.")])
    dob = DateField("Date of Birth", validators=[InputRequired()], format='%Y-%m-%d')
    recaptcha = RecaptchaField()
    reset_id_submit = SubmitField("Next")


class ResetFormAuthenticate(FlaskForm):
    token = StringField("2FA Token", validators=[InputRequired(), Length(min=6, max=6), Regexp(twoFaExp)],
                        render_kw={"placeholder": "OTP Token"})
    recaptcha = RecaptchaField()
    reset_auth_submit = SubmitField("Next")


class ResetPasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8),
                                                     EqualTo('confirm_password', message='Passwords must match'),
                                                     Regexp(
                                                         passExp,
                                                         message="Password complexity not met")])
    confirm_password = PasswordField("Confirm Password")
    recaptcha = RecaptchaField()
    reset_pwd_submit = SubmitField("Reset")


class AddTransfereeForm(FlaskForm):
    transferee_acc = StringField("Transferee Account No", validators=[InputRequired(), Length(min=10, max=10),
                                                                      Regexp("^\\d{10,10}$",
                                                                             message="Invalid account number")])
    recaptcha = RecaptchaField()
    add_transferee_submit = SubmitField("Add")


class SetTransferLimitForm(FlaskForm):
    transfer_limit = IntegerField("Set Transfer Limit", validators=[InputRequired()])
    recaptcha = RecaptchaField()
    set_transfer_submit = SubmitField("Set")


class TransferMoneyForm(FlaskForm):

    transferee_acc = SelectField("Transferee", coerce=str, validators=[InputRequired(), Length(min=10, max=40),
                                                                       Regexp("^\\d{10,10}\\s-\\s(?=.{1,40}$)[a-zA-Z]+(?:[-'\\s][a-zA-Z]+)*\\s(?=.{1,40}$)[a-zA-Z]+(?:[-'\\s][a-zA-Z]+)*$",
                                                                              message="Invalid account number")])
    amount = FloatField("Amount to Transfer.", validators=[InputRequired()])
    description = StringField("Description.", validators=[InputRequired(), Length(min=1, max=50),
                                                          Regexp("^[A-Za-z0-9$\\.\\s]", message="Invalid Characters")])
    recaptcha = RecaptchaField()
    transfer_money_submit = SubmitField("Transfer")


class TransferMoneyOneTimeForm(FlaskForm):
    transferee_acc = StringField("Transferee Account No", validators=[InputRequired(), Length(min=10, max=10),
                                                                      Regexp("^\\d{10,10}$",
                                                                             message="Invalid account number")])
    amount = FloatField("Amount to Transfer.", validators=[InputRequired()])
    description = StringField("Description.", validators=[InputRequired(), Length(min=1, max=50),
                                                          Regexp("^[A-Za-z0-9$\\.\\s]", message="Invalid Characters")])
    recaptcha = RecaptchaField()
    transfer_onetime_submit = SubmitField("Transfer")


class RemoveTransfereeForm(FlaskForm):
    transferee_acc = HiddenField(validators=[InputRequired(), Length(min=10, max=10), Regexp("^\\d{10,10}$",
                                                                                             message="Invalid account number")])
    submit = SubmitField("Remove")


class SecureMessageForm(FlaskForm):
    msg = HiddenField(validators=[InputRequired(), Regexp("^[\\d]+$", message="Invalid ID")])
    mark = SubmitField("Read")
    unmark = SubmitField("Unread")
    delete = SubmitField("Delete")


class TopUpForm(FlaskForm):
    amount = FloatField("Amount to Top Up", validators=[InputRequired()])
    recaptcha = RecaptchaField()
    topup_submit = SubmitField("Top Up")


class ManageUserForm(FlaskForm):
    userid = HiddenField(validators=[InputRequired(), Regexp("^[\\d]+$", message="Invalid ID")])
    disable = SubmitField("Disable")
    unlock = SubmitField("Unlock")
    delete = SubmitField("Delete")


class ApproveTransactionForm(FlaskForm):
    transactionid = HiddenField(validators=[InputRequired(), Regexp("^[\\d]+$", message="Invalid ID")])
    approve = SubmitField("Approve")
    reject = SubmitField("Reject")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[InputRequired(), Length(min=8),
                                                                     Regexp(
                                                                         passExp,
                                                                         message="Password complexity not met")],
                                     render_kw={"placeholder": "Password"})
    password = PasswordField("New Password", validators=[InputRequired(), Length(min=8),
                                                         EqualTo('confirm_password', message='Passwords must match'),
                                                         Regexp(
                                                             passExp,
                                                             message="Password complexity not met")])
    confirm_password = PasswordField("Confirm Password")
    token = StringField("2FA Token", validators=[InputRequired(), Length(min=6, max=6), Regexp(twoFaExp)],
                        render_kw={"placeholder": "OTP Token"})
    recaptcha = RecaptchaField()
    change_pwd_submit = SubmitField("Change")
