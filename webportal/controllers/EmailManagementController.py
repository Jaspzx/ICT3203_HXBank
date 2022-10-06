from flask_mail import Message as Mail_Message
from webportal import app, mail
from itsdangerous import URLSafeTimedSerializer


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
    def generate_token(arg_email):
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return serializer.dumps(arg_email, salt=app.config['SECURITY_PASSWORD_SALT'])

    @staticmethod
    def confirm_token(arg_token, expiration=3600):
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            email = serializer.loads(arg_token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
        except:
            return False
        return email
