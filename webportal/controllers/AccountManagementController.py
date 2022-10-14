import secrets
from webportal import flask_bcrypt
from webportal.utils.interact_db import *
from datetime import datetime, timedelta, date
from datetime import datetime
from webportal.models.Transferee import User
from webportal import flask_bcrypt


class AccountManagementController:
    @staticmethod
    def login_success(arg_user, arg_token):
        arg_user.session_token = secrets.token_urlsafe(20)
        arg_user.last_login = datetime.now()
        arg_user.failed_login_attempts = 0
        arg_user.prev_token = arg_token
        update_db_no_close()

    @staticmethod
    def login_fail(arg_user):
        arg_user.failed_login_attempts += 1
        if arg_user.failed_login_attempts > 3:
            arg_user.is_disabled = True
        update_db_no_close()

    @staticmethod
    def verify_details(username, email, mobile, nric, dob, age):
        # Check if the username exist. 
        if User.query.filter_by(username=username).first() is not None:
            return True, "Username already in use."

        # Check if the email exist. 
        if User.query.filter_by(email=email).first() is not None:
            return True, "Email already in use."

        # Check if the mobile number exist. 
        if User.query.filter_by(mobile=mobile).first() is not None:
            return True, "Mobile number already in use."

        # Check if nric exist. 
        if User.query.filter_by(nric=nric).first() is not None:
            return True, "Identification No. already in use."

        # Check if date and age are valid. 
        if dob > date.today():
            return True, "Invalid date"
        elif age < 16:
             return True, "You have to be at least 16 years old."
        return False, None 

    @staticmethod
    def add_user(username, firstname, lastname, address, email, mobile, nric, dob, password, otp_secret, token):
        new_user = User(username, firstname, lastname, address, email, mobile, nric, dob, password, None, token)
        add_db_no_close(new_user)

    @staticmethod
    def authenticate(user, password):
        # Check the user's password against the db. 
        if flask_bcrypt.check_password_hash(user.password_hash, password):
            
            # Check if the user's account is disabled.
            if user.is_disabled:
                error = "Account has been locked out. Please contact customer support for assistance."
                return 2
            
            # Redirect to input OTP page is user's account is not disabled. 
            return 1
        
        # Invalid attempt detected.
        else:
            # Increase failed login attempts. 
            user.failed_login_attempts += 1

            # Disable if login attempts is greater than 3. 
            if user.failed_login_attempts > 3:
                user.is_disabled = True
                return 4 

            # Update the db. 
            update_db()        

            return 3 

    @staticmethod
    def generate_pyotp(user):
        # Generate the pyotp secret. 
        user.otp_secret = pyotp.random_base32()
        update_db_no_close()        

    @staticmethod
    def reset_pwd(user, password):
        user.password_hash = password
        update_db()        

    @staticmethod
    def change_pw(user, password):
        user.password_hash = password
        update_db_no_close()        

    @staticmethod
    def unlock_account(user):
        user.is_disabled = False
        user.failed_login_attempts = 0
        update_db()

    @staticmethod
    def disable_account(user):
        user.is_disabled = True
        update_db()