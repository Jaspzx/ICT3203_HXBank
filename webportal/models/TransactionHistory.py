from webportal import db
from random import SystemRandom


class TransactionHistory(db.Model):
    id = db.Column(db.INT, primary_key=True)
    amt_transferred = db.Column(db.Float, nullable=False)
    transferer = db.Column(db.String(50), db.ForeignKey('user.id'))
    transferee = db.Column(db.String(50), db.ForeignKey('user.id'))
    require_approval = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, amt_transferred, transferer, transferee, require_approval):
        self.amt_transferred = amt_transferred
        self.transferer = transferer
        self.transferee = transferee
        self.require_approval = require_approval  

def createWelcomeTransaction(userid):
    welcome_amt = random_gen.randrange(10000)
    welcome_transaction = TransactionHistory(welcome_amt, None, userid, False)
    print("DONE")



def createTransaction():
    pass 


