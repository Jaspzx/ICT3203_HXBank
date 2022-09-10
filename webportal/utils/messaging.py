from webportal.models.Message import *
from webportal.models.User import *
from sqlalchemy import desc
from flask_login import current_user
from webportal import db


def load_nav_messages() -> list:
    msg_query = db.session.query(Message).join(User).filter(User.id == current_user.id).order_by(
        desc(Message.date_sent)).all()
    msg_data = []
    for message in msg_query:
        msg_dict = {"id": None, "sender": None, "message": None, "read": None, "date_sent": None}
        msg = db.session.query(Message).filter_by(id=message.id).first()
        msg_dict["id"] = msg.id
        msg_dict["sender"] = msg.sender
        msg_dict["message"] = msg.message
        msg_dict["read"] = msg.read
        msg_dict["date_sent"] = msg.date_sent
        msg_data.append(msg_dict)
    return msg_data


def welcome_msg(arg_amt) -> str:
    welcome = f"Welcome! As a welcome gift, ${arg_amt} has been debited to your account!"
    return welcome
