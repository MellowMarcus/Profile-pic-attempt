from werkzeug.security import check_password_hash, generate_password_hash
from App.database import db
from flask import jsonify
from flask_login import UserMixin
from datetime import datetime


class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	profile_pic = db.Column(db.String(), nullable=True)
	password_hash = db.Column(db.String(128))
	images = db.relationship('Image', backref='image', lazy=True, cascade="all, delete-orphan")
  	ratings = db.relationship('Rating', backref='rating', lazy=True, cascade="all, delete-orphan")
  	date_added = db.Column(db.DateTime, default=datetime.utcnow)
  
	def __init__(self, username, password_hash):
		self.username = username
		self.set_password(password_hash)
	
	def toJSON(self):
        	return{
            	'id': self.id,
            	'username': self.username,
            	'profile_pic': self.profile_pic,
            	'images': [image.toJSON() for image in self.images],
            	'ratings': [rating.toJSON() for rating in self.ratings],
            	'dateAdded' : self.dateAdded
        	}

	#Exception thrown
	@property
	def password(self):
		raise AttributeError('password is not a readable attribute!')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password, method='sha256')

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)
