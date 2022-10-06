from webportal.utils.interact_db import *
import secrets
from datetime import datetime


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
