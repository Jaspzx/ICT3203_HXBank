import secrets
import pyotp
import copy
from webportal.utils.interact_db import update_db_no_close, add_db_no_close, update_db, del_db
from datetime import date
from datetime import datetime
from webportal.models.User import User
from webportal import flask_bcrypt, encryptor


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
        enc_email = encryptor.encrypt(email)
        enc_mobile = encryptor.encrypt(mobile)
        enc_nric = encryptor.encrypt(nric)

        if User.query.filter_by(username=username).first() is not None:
            return True, "Username already in use."

        if User.query.filter_by(email=enc_email).first() is not None:
            return True, "Email already in use."

        if User.query.filter_by(mobile=enc_mobile).first() is not None:
            return True, "Mobile number already in use."

        if User.query.filter_by(nric=enc_nric).first() is not None:
            return True, "Identification No. already in use."

        if dob > date.today():
            return True, "Invalid date"
        elif age < 16:
            return True, "You have to be at least 16 years old."
        return False, None

    @staticmethod
    def add_user(username, firstname, lastname, address, email, mobile, nric, dob, password, otp_secret, token, perms):
        enc_firstname = encryptor.encrypt(firstname)
        enc_lastname = encryptor.encrypt(lastname)
        enc_address = encryptor.encrypt(address)
        enc_email = encryptor.encrypt(email)
        enc_mobile = encryptor.encrypt(mobile)
        enc_nric = encryptor.encrypt(nric)
        enc_dob = encryptor.encrypt(str(dob))
        if perms == 1:
            new_user = User(username, enc_firstname, enc_lastname, enc_address, enc_email, enc_mobile, enc_nric,
                            enc_dob, password, None, token, True)
        else:
            new_user = User(username, enc_firstname, enc_lastname, enc_address, enc_email, enc_mobile, enc_nric,
                            enc_dob, password, None, token, False)
        add_db_no_close(new_user)

    @staticmethod
    def decrypt_by_username(username):
        user = User.query.filter_by(username=username).first()
        if user is None:
            return None
        user_copy = copy.deepcopy(user)
        user_copy.firstname = encryptor.decrypt(user.firstname).decode()
        user_copy.lastname = encryptor.decrypt(user.lastname).decode()
        user_copy.address = encryptor.decrypt(user.address).decode()
        user_copy.email = encryptor.decrypt(user.email).decode()
        user_copy.mobile = encryptor.decrypt(user.mobile).decode()
        user_copy.nric = encryptor.decrypt(user.nric).decode()
        user_copy.dob = encryptor.decrypt(user.dob).decode()
        return user_copy

    @staticmethod
    def decrypt_by_id(id):
        user = User.query.filter_by(id=id).first()
        user_copy = copy.deepcopy(user)
        user_copy.firstname = encryptor.decrypt(user.firstname).decode()
        user_copy.lastname = encryptor.decrypt(user.lastname).decode()
        user_copy.address = encryptor.decrypt(user.address).decode()
        user_copy.email = encryptor.decrypt(user.email).decode()
        user_copy.mobile = encryptor.decrypt(user.mobile).decode()
        user_copy.nric = encryptor.decrypt(user.nric).decode()
        user_copy.dob = encryptor.decrypt(user.dob).decode()
        return user_copy

    @staticmethod
    def authenticate(user, password):
        if flask_bcrypt.check_password_hash(user.password_hash, password):
            if user.is_disabled:
                return 2
            return 1
        else:
            user.failed_login_attempts += 1
            if user.failed_login_attempts > 3:
                user.is_disabled = True
                user.failed_login_attempts = 0
                update_db_no_close()
                return 4
            update_db_no_close()
            return 3

    @staticmethod
    def generate_pyotp(user):
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

    @staticmethod
    def delete_account(user):
        del_db(user)
