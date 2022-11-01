from webportal import db
from datetime import datetime


class Transaction(db.Model):
    id = db.Column(db.INT, primary_key=True)
    date_transferred = db.Column(db.DateTime(timezone=True), nullable=False)
    amt_transferred = db.Column(db.Float, nullable=False)
    transferrer_acc_number = db.Column(db.String(10), db.ForeignKey('account.acc_number'), nullable=False)
    transferee_acc_number = db.Column(db.String(10), db.ForeignKey('account.acc_number'), nullable=False)
    description = db.Column(db.String(50), nullable=False)
    require_approval = db.Column(db.Boolean, default=False, nullable=False)
    status = db.Column(db.INT, default=False, nullable=False)

    def __init__(self, amt_transferred, transferrer_acc_number, transferee_acc_number, description, require_approval, status):
        self.date_transferred = datetime.now()
        self.amt_transferred = amt_transferred
        self.transferrer_acc_number = transferrer_acc_number
        self.transferee_acc_number = transferee_acc_number
        self.description = description
        self.require_approval = require_approval
        self.status = status
