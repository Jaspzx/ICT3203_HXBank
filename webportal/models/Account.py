from datetime import datetime, timedelta
from webportal import db


class Account(db.Model):
	acc_number = db.Column(db.String(10), nullable=False, primary_key=True, unique=True)
	acc_balance = db.Column(db.Float, nullable=False)
	acc_xfer_limit = db.Column(db.Float, nullable=False)
	acc_xfer_daily = db.Column(db.Float, nullable=False)
	money_on_hold = db.Column(db.Float, nullable=False)
	reset_set_xfer_limit_date = db.Column(db.DateTime(timezone=True), nullable=False)
	reset_xfer_limit_date = db.Column(db.DateTime(timezone=True), nullable=False)
	userid = db.Column(db.INT, db.ForeignKey('user.id'), unique=True)

	def __init__(self, acc_number, userid, acc_balance):
		self.acc_number = acc_number
		self.acc_balance = acc_balance
		self.acc_xfer_limit = 1000
		self.acc_xfer_daily = 0 
		self.money_on_hold = 0
		self.reset_set_xfer_limit_date = datetime.now()
		self.reset_xfer_limit_date = datetime.now() + timedelta(days=1)
		self.userid = userid
