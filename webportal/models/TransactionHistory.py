class TransactionHistory(db.Model):
    id = db.Column(db.INT, primary_key=True)
    amt_transferred = db.Column(db.Float, nullable=False)
    transfer = db.Column(db.String(50), db.ForeignKey('user.id'))
    transferee = db.Column(db.String(50), db.ForeignKey('user.id'))
    require_approval = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self):
        pass 

def createWelcomeTransaction():
    pass 

def createTransaction():
    pass 


