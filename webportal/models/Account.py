from datetime import datetime, timedelta, date
from webportal import db
from random import SystemRandom
from webportal.models.Transaction import *
from ..utils.messaging import *


class Account(db.Model):
	acc_number = db.Column(db.String(10), nullable=False, primary_key=True)
	acc_balance = db.Column(db.Numeric(precision=2, asdecimal=False, decimal_return_scale=None))
	acc_xfer_limit = db.Column(db.Numeric(precision=2, asdecimal=False, decimal_return_scale=None))
	acc_xfer_daily = db.Column(db.Numeric(precision=2, asdecimal=False, decimal_return_scale=None))
	money_on_hold = db.Column(db.Numeric(precision=2, asdecimal=False, decimal_return_scale=None))
	reset_xfer_limit_date = db.Column(db.DateTime(timezone=True), nullable=False)
	userid = db.Column(db.INT, db.ForeignKey('user.id'))

	def __init__(self, acc_number, userid, acc_balance):
		self.acc_number = acc_number
		self.acc_balance = acc_balance
		self.acc_xfer_limit = 1000
		self.acc_xfer_daily = 0 
		self.money_on_hold = 0 
		self.reset_xfer_limit_date = datetime.now() + timedelta(days=1)
		self.userid = userid
