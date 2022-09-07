from webportal import db
from random import SystemRandom
from webportal.models.Transaction import *


class Account(db.Model):
	id = db.Column(db.INT, primary_key=True)
	acc_balance = db.Column(db.Float, nullable=False)
	acc_xfer_limit = db.Column(db.INT, nullable=False)
	acc_number = db.Column(db.String(10), nullable=False)
	userid = db.Column(db.INT, db.ForeignKey('user.id'))

	def __init__(self, acc_number, userid, acc_balance):
		print(acc_balance)
		self.acc_balance = acc_balance
		self.acc_xfer_limit = 1000
		self.acc_number = acc_number
		self.userid = userid


def createAccount(userid):
	random_gen = SystemRandom()
	acc_number = "".join([str(random_gen.randrange(9)) for i in range(10)])
	welcome_amt = random_gen.randrange(1000, 10000)
	new_account = Account(acc_number, userid, welcome_amt)
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


def updateBalance(transferrer_id, transferee_id, amount):
	transferrer_acc = Account.query.filter_by(userid=transferrer_id).first()
	transferee_acc = Account.query.filter_by(userid=transferee_id).first()
	transferrer_acc.acc_balance -= amount
	transferee_acc.acc_balance += amount 
	try:
		db.session.commit()
	except:
		db.session.rollback()
	finally:
		db.session.close()




