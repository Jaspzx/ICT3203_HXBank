from webportal import db
from datetime import datetime


class Message(db.Model):
    id = db.Column(db.INT, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    read = db.Column(db.Boolean, default=False, nullable=False)
    date_sent = db.Column(db.DateTime(timezone=True), nullable=False)
    userid = db.Column(db.INT, db.ForeignKey('user.id'))

    def __init__(self, message, userid):
        self.sender = "HX Bank"
        self.message = message
        self.date_sent = datetime.now()
        self.userid = userid


def message_add(arg_message, arg_userid):
    new_message = Message(arg_message, arg_userid)
    try:
        db.session.add(new_message)
        db.session.commit()
    except:
        db.session.rollback()


def message_read(arg_message):
    arg_message.read = True
    try:
        db.session.add(arg_message)
        db.session.commit()
    except:
        db.session.rollback()


def message_del(arg_message):
    try:
        db.session.delete(arg_message)
        db.session.commit()
    except:
        db.session.rollback()
