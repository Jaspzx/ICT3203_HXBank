from webportal import db
from random import SystemRandom


class Account(db.Model):
    id = db.Column(db.INT, primary_key=True)
    acc_balance = db.Column(db.Float, nullable=False)
    acc_xfer_limit = db.Column(db.INT, nullable=False)
    acc_number = db.Column(db.String(10), nullable=False)
    userid = db.Column(db.String(50), db.ForeignKey('user.id'))

    def __init__(self, acc_number, userid):
        self.acc_balance = 0 
        self.acc_xfer_limit = 1000
        self.acc_number = acc_number
        self.userid = userid

def createAccount(userid):
    random_gen = SystemRandom() 
    acc_number = "".join([str(random_gen.randrange(9)) for i in range(10)])
    new_account = Account(acc_number, userid)
    try:
        db.session.add(new_account)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()
