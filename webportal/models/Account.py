from datetime import datetime, timedelta, date
from webportal import db
from random import SystemRandom
from webportal.models.Transaction import *
from ..utils.messaging import *


class Account(db.Model):
	acc_number = db.Column(db.String(10), nullable=False, primary_key=True)
	acc_balance = db.Column(db.Float, nullable=False)
	acc_xfer_limit = db.Column(db.INT, nullable=False)
	acc_xfer_daily = db.Column(db.Float, nullable=False)
	reset_xfer_limit_date = db.Column(db.DateTime(timezone=True), nullable=False)
	userid = db.Column(db.INT, db.ForeignKey('user.id'))

	def __init__(self, acc_number, userid, acc_balance):
		self.acc_number = acc_number
		self.acc_balance = acc_balance
		self.acc_xfer_limit = 1000
		self.acc_xfer_daily = 0 
		self.reset_xfer_limit_date = datetime.now() + timedelta(days=1)
		self.userid = userid


def createAccount(userid):
	random_gen = SystemRandom()
	acc_number = "".join([str(random_gen.randrange(9)) for i in range(10)])
	welcome_amt = random_gen.randrange(1000, 10000)
	new_account = Account(acc_number, userid, welcome_amt)
	message_add(welcome_msg(welcome_amt), userid)
	try:
		db.session.add(new_account)
		db.session.commit()
	except:
		db.session.rollback()
	finally:
		db.session.close()


def setTransferLimit(userid, transfer_limit):
	acc = Account.query.filter_by(userid=userid).first()
	acc.acc_xfer_limit = transfer_limit
	try:
		db.session.commit()
	except:
		db.session.rollback()
	finally:
		db.session.close()


def topup(userid, amount):
	acc = Account.query.filter_by(userid=userid).first()
	acc.acc_balance += amount 
	try:
		db.session.commit()
	except:
		db.session.rollback()
	finally:
		db.session.close()	


def updateBalance(transferrer_id, transferee_id, amount):
	transferrer_acc = Account.query.filter_by(userid=transferrer_id).first()
	transferee_acc = Account.query.filter_by(userid=transferee_id).first()
	transferrer_acc.acc_balance -= amount
	transferee_acc.acc_balance += amount 
	if datetime.now().date() > transferee_acc.reset_xfer_limit_date.date():
		transferee_acc.reset_xfer_limit = date.today() + timedelta(days=1)
		transferrer_acc.acc_xfer_daily = 0
	transferrer_acc.acc_xfer_daily += amount 
	try:
		db.session.commit()
	except:
		db.session.rollback()
	finally:
		db.session.close()
