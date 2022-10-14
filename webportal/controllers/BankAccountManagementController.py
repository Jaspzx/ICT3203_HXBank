import secrets
from decimal import Decimal
from webportal.utils.interact_db import *
from random import SystemRandom
from webportal.models.Transferee import *
from webportal.models.Account import *
from webportal.models.User import *

# Global variables.
TWO_PLACES = Decimal(10) ** -2


class BankAccountManagementController:
    @staticmethod
    def add_bank_account(user_id, welcome_amt, acc_number):
        new_account = Account(acc_number, user_id, welcome_amt)
        add_db_no_close(new_account)

    @staticmethod
    def populate_transfer_money_form(user_id):
        transferee_data = Transferee.query.filter_by(transferer_id=user_id).all()
        data = []
        for transferee in transferee_data:
            transferee_acc_data = Account.query.filter_by(userid=transferee.transferee_id).first()
            acc_num = transferee_acc_data.acc_number
            transferee_user_data = User.query.filter_by(id=transferee.transferee_id).first()
            first_name = transferee_user_data.firstname
            last_name = transferee_user_data.lastname
            user_data = f"{acc_num} - {first_name} {last_name}"
            data.append(user_data)
        return data

    @staticmethod
    def transfer_money_checks(amount, transferee_acc_number, transferrer_acc):
        # Amount to debit and credit from transferee and transferrer respectively.
        if amount < 0.1:
            error = "Invalid amount (Minimum $0.10)"
            return error, None

        # Get the transferee's account information.
        # transferee_userid = Account.query.filter_by(acc_number=transferee_acc_number).first().userid
        # transferee_user = Account.query.filter_by(acc_number=transferee_acc_number).first()

        # Check that the amount to be transferred does not exceed the transfer limit.
        day_amount = Decimal(transferrer_acc.acc_xfer_daily + amount).quantize(TWO_PLACES)
        if datetime.now().date() < transferrer_acc.reset_xfer_limit_date.date() and day_amount > transferrer_acc.acc_xfer_limit:
            error = "Amount to be transferred exceeds daily transfer limit"
            return error, transferrer_acc.acc_balance

        # Check that the bank account has sufficient funds for a transfer. 
        if transferrer_acc.acc_balance - transferrer_acc.money_on_hold < amount:
            error = "Insufficient funds"
            return error, transferrer_acc.acc_balance

        return None, transferrer_acc.acc_balance

    @staticmethod
    def create_transaction(amount, transferer_acc, transferee_acc, description):
        require_approval = False
        status = 0

        if amount >= 10000:
            require_approval = True
            status = 1

        new_transaction = Transaction(Decimal(amount).quantize(TWO_PLACES), transferer_acc.acc_number,
                                      transferee_acc.acc_number, description, require_approval, status)
        add_db_no_close(new_transaction)

        # Add money to onhold if approval is required. 
        if require_approval:
            money_on_hold = Decimal(transferer_acc.money_on_hold + amount).quantize(TWO_PLACES)
            transferer_acc.money_on_hold = money_on_hold

        else:
            # Update the balance for both transferer and transferee.
            transferer_acc.acc_balance = Decimal(transferer_acc.acc_balance - amount).quantize(TWO_PLACES)
            transferee_acc_balance = Decimal(transferee_acc.acc_balance - amount).quantize(TWO_PLACES)
            transferee_acc.acc_balance = transferee_acc_balance
            if datetime.now().date() > transferee_acc.reset_xfer_limit_date.date():
                transferee_acc.reset_xfer_limit = date.today() + timedelta(days=1)
                transferer_acc.acc_xfer_daily = 0
            transferrer_acc_xfer_daily = Decimal(transferer_acc.acc_xfer_daily + amount).quantize(TWO_PLACES)
            transferer_acc.acc_xfer_daily = transferrer_acc_xfer_daily

        update_db_no_close()

        return require_approval, transferer_acc.acc_number, transferee_acc.acc_number

    @staticmethod
    def add_transferee_checks(transferer_id, transferee_acc):
        # Check that the transferee info does not exist already in the current user's transferee list.
        if transferee_acc:
            validate_if_exist = Transferee.query.filter_by(transferer_id=transferer_id,
                                                           transferee_id=transferee_acc.userid).first()

            # Return error if it exists.
            if validate_if_exist:
                add_error = "Transferee already exists!"
                return add_error

            else:
                return None
        # Return error if the transferee info does not exist based on the account number provided by the user.
        else:
            add_error = "Invalid account!"
            return add_error

    @staticmethod
    def add_transferee(transferer_id, transferee_acc):
        new_transferee = Transferee(current_user.id, transferee_acc.userid)
        add_db_no_close(new_transferee)

    @staticmethod
    def transaction_history(user_id):
        # Get the list of transactions that the user is involved in.
        user_acc_number = Account.query.filter_by(userid=current_user.id).first().acc_number
        transfer_data = Transaction.query.filter_by(transferrer_acc_number=user_acc_number).all()
        transferee_data = Transaction.query.filter_by(transferee_acc_number=user_acc_number).all()
        data = []

        # Combine the transactions together.
        for item in reversed(transfer_data):
            data.append({"date_transferred": item.date_transferred.strftime('%Y-%m-%d %H:%M:%S'),
                         "amt_transferred": Decimal(item.amt_transferred).quantize(TWO_PLACES),
                         "transferrer_acc": item.transferrer_acc_number, "transferee_acc": item.transferee_acc_number,
                         "description": item.description, "require_approval": item.require_approval,
                         "status": item.status,
                         "debit": False})
        for item in reversed(transferee_data):
            if item.transferrer_acc_number != item.transferee_acc_number:
                data.append({"date_transferred": item.date_transferred.strftime('%Y-%m-%d %H:%M:%S'),
                             "amt_transferred": Decimal(item.amt_transferred).quantize(TWO_PLACES),
                             "transferrer_acc": item.transferrer_acc_number,
                             "transferee_acc": item.transferee_acc_number,
                             "description": item.description, "require_approval": item.require_approval,
                             "status": item.status, "debit": True})

        # Sort by latest date first.
        data = {x['date_transferred']: x for x in data}.values()

        return data

    @staticmethod
    def view_transferee(user_id):
        transferee_data = Transferee.query.filter_by(transferer_id=user_id).all()
        data = []
        form_data_list = []
        for transferee in transferee_data:
            transferee_acc_data = Account.query.filter_by(userid=transferee.transferee_id).first()
            acc_num = transferee_acc_data.acc_number
            transferee_user_data = User.query.filter_by(id=transferee.transferee_id).first()
            first_name = transferee_user_data.firstname
            last_name = transferee_user_data.lastname
            user_data = {"acc_num": acc_num, "first_name": first_name, "last_name": last_name}
            form_data = f"{acc_num} - {first_name} {last_name}"
            data.append(user_data)
            form_data_list.append(form_data)
        return form_data_list, data

    @staticmethod
    def remove_transferee(transferee_acc):
        transferee_id = Account.query.filter_by(acc_number=transferee_acc).first().userid
        Transferee.query.filter_by(transferer_id=current_user.id, transferee_id=transferee_id).delete()
        update_db()

    @staticmethod
    def set_transfer_limit(user_id, amount):
        if amount < 0.1:
            error = "Invalid value"
            return error
        acc = Account.query.filter_by(userid=user_id).first()
        acc.acc_xfer_limit = Decimal(amount).quantize(TWO_PLACES)
        update_db_no_close()
        return None

    @staticmethod
    def topup_balance(user_id, user_acc, amount, description):
        if amount < 1:
            error = "Invalid amount (Minimum $1)"
            return error
        acc = Account.query.filter_by(userid=user_id).first()
        acc_balance = Decimal(acc.acc_balance + amount).quantize(TWO_PLACES)
        acc.acc_balance = acc_balance

        # Create transaction
        new_transaction = Transaction(amount, user_acc, user_acc, description, False, 0)
        add_db_no_close(new_transaction)

        update_db_no_close()
        return None
