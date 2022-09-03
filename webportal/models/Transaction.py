from webportal import db
from random import SystemRandom
from webportal.models.Account import *


class Transaction(db.Model):
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

def createTransaction():
    pass 


