from webportal import db
from random import SystemRandom
from webportal.models.Account import *
from datetime import datetime, timedelta


class Transaction(db.Model):
    id = db.Column(db.INT, primary_key=True)
    date_transferred = db.Column(db.DateTime(timezone=True), nullable=False)
    amt_transferred = db.Column(db.Float, nullable=False)
    transferer_id = db.Column(db.String(50), db.ForeignKey('user.id'))
    transferee_id = db.Column(db.String(50), db.ForeignKey('user.id'))
    require_approval = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, amt_transferred, transferer, transferee, require_approval):
        self.date_transferred = datetime.now()
        self.amt_transferred = amt_transferred
        self.transferer = transferer
        self.transferee = transferee
        self.require_approval = require_approval


def createTransaction(amt_transferred, transferrer_id, transferee_id, require_approval):
    new_transaction = Transaction(amt_transferred, transferrer_id, transferee_id, require_approval)
    try:
        db.session.add(new_transaction)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()    