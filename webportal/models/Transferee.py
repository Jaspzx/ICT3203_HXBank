from webportal import db
from random import SystemRandom
from webportal.models.Account import *
from datetime import datetime, timedelta


class Transferee(db.Model):
    id = db.Column(db.INT, primary_key=True)
    date_added = db.Column(db.DateTime(timezone=True), nullable=False)
    transferer_id = db.Column(db.INT, db.ForeignKey('user.id'))
    transferee_id = db.Column(db.INT, db.ForeignKey('user.id'))

    def __init__(self, transferer_id, transferee_id):
        self.date_added = datetime.now()
        self.transferer_id = transferer_id
        self.transferee_id = transferee_id
