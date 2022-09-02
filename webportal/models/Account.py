from webportal import db


class Account(db.Model):
    id = db.Column(db.INT, primary_key=True)
    acc_balance = db.Column(db.INT, nullable=False)
    acc_xfer_limit = db.Column(db.INT, nullable=False)
    acc_number = db.Column(db.INT, nullable=False)
