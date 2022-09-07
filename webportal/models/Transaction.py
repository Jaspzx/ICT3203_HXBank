from webportal import db
from random import SystemRandom
from webportal.models.Account import *
from datetime import datetime, timedelta


class Transaction(db.Model):
    id = db.Column(db.INT, primary_key=True)
    date_transferred = db.Column(db.DateTime(timezone=True), nullable=False)
    amt_transferred = db.Column(db.Numeric(precision=2, asdecimal=False, decimal_return_scale=None))
    transferrer_acc_number = db.Column(db.String(10), db.ForeignKey('account.acc_number'))
    transferee_acc_number = db.Column(db.String(10), db.ForeignKey('account.acc_number'))
    require_approval = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, amt_transferred, transferrer_acc_number, transferee_acc_number, require_approval):
        self.date_transferred = datetime.now()
        self.amt_transferred = amt_transferred
        self.transferrer_acc_number = transferrer_acc_number
        self.transferee_acc_number = transferee_acc_number
        self.require_approval = require_approval


def createTransaction(amt_transferred, transferrer_acc_number, transferee_acc_number, require_approval):
    new_transaction = Transaction(amt_transferred, transferrer_acc_number, transferee_acc_number, require_approval)
    try:
        db.session.add(new_transaction)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()    