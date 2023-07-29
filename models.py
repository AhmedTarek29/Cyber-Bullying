from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin

bcrypt = Bcrypt()
db = SQLAlchemy()

# Define the friends table
friend = db.Table('friends',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('friend_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    gender = db.Column(db.String(6), nullable=False)
    birthdate = db.Column(db.String(10), nullable=False)
    tweets = db.relationship('Tweet', backref='user', lazy=True)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    ban_duration = db.Column(db.Integer, default=False)
    friends = db.relationship('User', secondary=friend,
                            primaryjoin=(friend.c.user_id == id),
                            secondaryjoin=(friend.c.friend_id == id),
                            lazy='dynamic')
    bullying_messages = db.relationship('BullyingMessage', backref='user', lazy=True)
    reports = db.relationship('Report', backref='user', lazy=True)
    
    def get_friends_count(self):
        return len(self.friends.all())

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

likes = db.Table('likes',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('tweet_id', db.Integer, db.ForeignKey('tweet.id'), primary_key=True)
)

class Tweet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(280), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prediction = db.Column(db.Integer, nullable=True)
    likes = db.relationship('User', secondary=likes, backref=db.backref('liked_tweets', lazy='dynamic'))
    likes_count = db.Column(db.Integer, default=0)

    def increment_likes_count(self):
        self.likes_count += 1

    def decrement_likes_count(self):
        self.likes_count -= 1

class BullyingMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"BullyingMessage('{self.text}', '{self.timestamp}')"

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tweet_id = db.Column(db.Integer, db.ForeignKey('tweet.id'), nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    author = db.relationship('User', backref=db.backref('reported_reports', cascade='all, delete'))
    tweet = db.relationship('Tweet', backref=db.backref('reports', cascade='all, delete'))
