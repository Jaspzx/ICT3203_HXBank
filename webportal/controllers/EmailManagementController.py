from flask_mail import Message as Mail_Message
from webportal import app, mail
from itsdangerous import URLSafeTimedSerializer
from webportal.utils.interact_db import *
from webportal.models.Transferee import User


class EmailManagementController:
    def __init__(self):
        self.subject = ""
        self.template = ""

    def send_email(self, arg_to, arg_subject, arg_template) -> None:
        self.subject = arg_subject
        self.template = arg_template
        try:
            email = Mail_Message(self.subject, recipients=[arg_to], html=self.template,
                                 sender=app.config['MAIL_DEFAULT_SENDER'])
            mail.send(email)
        except:
            pass

    @staticmethod
    def generate_token(arg_username, user):
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        token = serializer.dumps(arg_username, salt=app.config['SECURITY_PASSWORD_SALT'])
        user.email_token = token
        update_db_no_close()
        return token

    @staticmethod
    def nullify_token(user):
        user.email_token = None
        update_db()

    @staticmethod
    def confirm_token(arg_token, expiration=3600):
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            username = serializer.loads(arg_token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
        except:
            return False
        return username

    @staticmethod
    def verify_token(username, token):
        user = User.query.filter_by(username=username).first()

        # Abort if not match.
        if user.email_token != token:
            return False

        # Redirect if matches. 
        elif user.email_verified:
            return True
        else:
            user.email_verified = True
            user.email_token = None
            update_db()
            return True
