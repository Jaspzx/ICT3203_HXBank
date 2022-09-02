from flask_login import UserMixin
from datetime import datetime 
from webportal import db

class User(db.Model, UserMixin):
	id = db.Column(db.INT, primary_key=True)
	username = db.Column(db.String(50))
	firstname = db.Column(db.String(50))
	lastname = db.Column(db.String(50))
	address = db.Column(db.String(50))
	email = db.Column(db.String(150))
	password_hash = db.Column(db.String(150))
	date_joined = db.Column(db.DateTime())

	def __init__(self, username, firstname, lastname, address, email, password_hash): 
		self.username = username
		self.firstname = firstname
		self.lastname = lastname
		self.address = address
		self.email = email
		self.password_hash = password_hash
		self.date_joined = datetime.now()

def createUser(username, firstname, lastname, address, email, password):
	new_user = User(username, firstname, lastname, address, email, password)
	try:
		db.session.add(new_user)
		db.session.commit()	
	except:
		db.session.rollback()
	finally: 
		db.session.close()    

def delUser():
	pass 