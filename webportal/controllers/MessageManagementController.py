from webportal.models.Message import *
from webportal.utils.interact_db import add_db_no_close, update_db, del_db


class MessageManagementController:
    def __init__(self):
        self.message = ""

    def create_message(self, arg_user) -> None:
        new_message = Message("HX-Bank", self.message, arg_user.id)
        add_db_no_close(new_message)

    def send_welcome_msg(self, arg_amt, arg_user) -> None:
        self.message = f"Welcome! As a welcome gift, ${arg_amt} has been debited to your account!"
        self.create_message(arg_user)

    def send_incorrect_attempts(self, arg_user) -> None:
        self.message = f"There were {arg_user.failed_login_attempts} failed login attempt(s) between your " \
                       f"current and last session"
        self.create_message(arg_user)

    def send_last_login(self, arg_user) -> None:
        self.message = f"You have logged in on {arg_user.last_login.strftime('%Y-%m-%d %H:%M:%S')}"
        self.create_message(arg_user)

    def send_otp_reset(self, arg_user) -> None:
        self.message = f"You have performed a OTP secret reset on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.create_message(arg_user)

    def send_password_reset(self, arg_user) -> None:
        self.message = f"You have performed a password reset on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.create_message(arg_user)

    def send_pending_transfer(self, arg_amt, arg_transferee_acc_data, arg_user) -> None:
        self.message = f"Your requested transfer of ${arg_amt} to {arg_transferee_acc_data} is currently pending for " \
                       f"approval."
        self.create_message(arg_user)

    def send_success_transfer(self, arg_amt, arg_transferee_acc_data, arg_user) -> None:
        self.message = f"Your requested transfer of ${arg_amt} to {arg_transferee_acc_data} is successful."
        self.create_message(arg_user)

    def send_add_acc_no(self, arg_acc_no, arg_user) -> None:
        self.message = f"You have added account number: {arg_acc_no}, as a transfer recipient"
        self.create_message(arg_user)

    def send_transfer_limit(self, arg_amt, arg_user) -> None:
        self.message = f"Your new transfer limit is ${arg_amt}"
        self.create_message(arg_user)

    def send_top_up(self, arg_amt, arg_user) -> None:
        self.message = f"You have made a request to top up ${arg_amt}"
        self.create_message(arg_user)

    def send_password_change(self, arg_user) -> None:
        self.message = f"You have performed a password change on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.create_message(arg_user)

    @staticmethod
    def mark_message(msg):
        msg.read = True
        update_db()

    @staticmethod
    def unmark_message(msg):
        msg.read = False
        update_db()

    @staticmethod
    def del_messasge(msg):
        del_db(msg)
