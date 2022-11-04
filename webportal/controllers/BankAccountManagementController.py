from datetime import timedelta
import secrets
from decimal import Decimal
from flask_login import current_user
from random import SystemRandom
from markupsafe import Markup
from webportal.models.Transferee import Transferee
from webportal.models.Transaction import Transaction
from webportal.models.Account import Account
from webportal.utils.interact_db import update_db_no_close, add_db_no_close, update_db
from datetime import datetime
from .AccountManagementController import AccountManagementController

TWO_PLACES = Decimal(10) ** -2


class BankAccountManagementController:
    @staticmethod
    def add_bank_account(user_id: int) -> [int, int]:
        random_gen = SystemRandom()
        welcome_amt = random_gen.randrange(1000, 10000)
        while True:
            acc_number = "".join([str(random_gen.randrange(9)) for _ in range(10)])
            exist = Account.query.filter_by(acc_number=acc_number).first()
            if exist is None:
                new_account = Account(acc_number, user_id, welcome_amt)
                add_db_no_close(new_account)
                break
        return acc_number, welcome_amt

    @staticmethod
    def transfer_money_checks(amount: float, transferrer_acc: Account, transferee_acc: Markup) -> [str, Decimal, None]:
        transferee_user = Account.query.filter_by(acc_number=transferee_acc).first()
        if transferee_user is None:
            error = "Invalid account number"
            return error, Decimal(transferrer_acc.acc_balance).quantize(TWO_PLACES), None

        if amount < 0.1:
            error = "Invalid amount (Minimum $0.10)"
            return error, Decimal(transferrer_acc.acc_balance).quantize(TWO_PLACES), None

        day_amount = Decimal(transferrer_acc.acc_xfer_daily + amount).quantize(TWO_PLACES)
        if datetime.now().date() < transferrer_acc.reset_xfer_limit_date.date() and day_amount > transferrer_acc.acc_xfer_limit:
            error = "Amount to be transferred exceeds daily transfer limit"
            return error, Decimal(transferrer_acc.acc_balance).quantize(TWO_PLACES), None

        if transferrer_acc.acc_balance - transferrer_acc.money_on_hold < amount:
            error = "Insufficient funds"
            return error, Decimal(transferrer_acc.acc_balance).quantize(TWO_PLACES), None

        return None, transferrer_acc.acc_balance, transferee_user

    @staticmethod
    def create_transaction(amount: float, transferer_acc: Account, transferee_acc: Account, description: str) -> [bool, Account, Account]:
        require_approval = False
        status = 0

        if amount >= 10000:
            require_approval = True
            status = 1

        new_transaction = Transaction(Decimal(amount).quantize(TWO_PLACES), transferer_acc.acc_number,
                                      transferee_acc.acc_number, description, require_approval, status)
        add_db_no_close(new_transaction)

        if require_approval:
            transferer_acc.money_on_hold = Decimal(transferer_acc.money_on_hold + amount).quantize(TWO_PLACES)
        else:
            transferer_acc.acc_balance = Decimal(transferer_acc.acc_balance - amount).quantize(TWO_PLACES)
            transferee_acc_balance = Decimal(transferee_acc.acc_balance + amount).quantize(TWO_PLACES)
            transferee_acc.acc_balance = transferee_acc_balance

        if datetime.now().date() > transferer_acc.reset_xfer_limit_date.date():
            transferer_acc.reset_xfer_limit_date = datetime.now() + timedelta(days=1)
            transferer_acc.acc_xfer_daily = 0

        transferer_acc.acc_xfer_daily = Decimal(transferer_acc.acc_xfer_daily + amount).quantize(TWO_PLACES)
        update_db_no_close()
        return require_approval, transferer_acc.acc_number, transferee_acc.acc_number

    @staticmethod
    def add_transferee_checks(transferer_id: int, transferee_acc: Markup) -> [str, None]:
        transferee_acc = Account.query.filter_by(acc_number=transferee_acc).first()
        if transferee_acc:
            validate_if_exist = Transferee.query.filter_by(transferer_id=transferer_id,
                                                           transferee_id=transferee_acc.userid).first()
            if validate_if_exist:
                add_error = "Transferee already exists"
                return add_error
            else:
                transferer_acc = Account.query.filter_by(userid=transferer_id).first().acc_number
                if transferer_acc == transferee_acc.acc_number:
                    add_error = "Unable to add own account to transferee list"
                    return add_error
                else:
                    return None
        else:
            add_error = "Invalid account"
            return add_error

    @staticmethod
    def add_transferee(transferer_id: int, transferee_acc: Markup) -> Account:
        transferee_acc = Account.query.filter_by(acc_number=transferee_acc).first()
        new_transferee = Transferee(transferer_id, transferee_acc.userid)
        add_db_no_close(new_transferee)
        return transferee_acc

    @staticmethod
    def transaction_history(user_id: int) -> dict.values:
        user_acc_number = Account.query.filter_by(userid=user_id).first().acc_number
        transfer_data = Transaction.query.filter_by(transferrer_acc_number=user_acc_number).all()
        transferee_data = Transaction.query.filter_by(transferee_acc_number=user_acc_number).all()
        data = []

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
        data = {x['date_transferred']: x for x in data}.values()
        return data

    @staticmethod
    def view_transferee(user_id: int) -> [list, list]:
        transferee_data = Transferee.query.filter_by(transferer_id=user_id).all()
        data = []
        form_data_list = []
        for transferee in transferee_data:
            transferee_acc_data = Account.query.filter_by(userid=transferee.transferee_id).first()
            acc_num = transferee_acc_data.acc_number
            amc = AccountManagementController()
            transferee_user_data = amc.decrypt_by_id(transferee.transferee_id)
            first_name = transferee_user_data.firstname
            last_name = transferee_user_data.lastname
            user_data = {"acc_num": acc_num, "first_name": first_name, "last_name": last_name}
            form_data = f"{acc_num} - {first_name} {last_name}"
            data.append(user_data)
            form_data_list.append(form_data)
        return form_data_list, data

    @staticmethod
    def remove_transferee(transferee_acc: Markup) -> None:
        transferee_id = Account.query.filter_by(acc_number=transferee_acc).first().userid
        Transferee.query.filter_by(transferer_id=current_user.id, transferee_id=transferee_id).delete()
        update_db()

    @staticmethod
    def set_transfer_limit(user_id: int, amount: float) -> [str, None]:
        if amount < 0.1:
            error = "Invalid value"
            return error
        acc = Account.query.filter_by(userid=user_id).first()
        if datetime.now().date() < acc.reset_set_xfer_limit_date.date():
            error = "Transfer limit can only be set once a day!"
            return error
        acc.reset_set_xfer_limit_date = datetime.now() + timedelta(days=1)
        acc.acc_xfer_limit = Decimal(amount).quantize(TWO_PLACES)
        update_db_no_close()
        return None

    @staticmethod
    def topup_balance(user_id: int, user_acc: Account, amount: float, description: str) -> [str, None]:
        if amount < 1:
            error = "Invalid amount (Minimum $1)"
            return error
        acc = Account.query.filter_by(userid=user_id).first()
        acc_balance = Decimal(acc.acc_balance + amount).quantize(TWO_PLACES)
        acc.acc_balance = acc_balance
        new_transaction = Transaction(amount, user_acc, user_acc, description, False, 0)
        add_db_no_close(new_transaction)
        update_db_no_close()
        return None
