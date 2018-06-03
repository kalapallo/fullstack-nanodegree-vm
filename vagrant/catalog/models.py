from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

import datetime

from passlib.apps import custom_app_context as pwd_context

import random
import string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer,
    BadSignature, SignatureExpired)

Base = declarative_base()

secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits)
    for x in xrange(32))


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    email = Column(String(64), index=True)
    password_hash = Column(String(64))

    # Actually not used at all
    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        """
        generate_auth_token: Generate an authorization token.
        Args:
            expiration (int): expiration time in seconds
        Returns:
            Auth token string
        """
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        """
        verify_auth_token: Verify an authorization token.
        Args:
            token (str): authorization token
        Returns:
            User ID encrypted in the token, or None if invalid token
        """
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String, index=True)
    items = relationship("Item")

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        'id' : self.id,
        'name' : self.name,
        'Item' : self.serialize_children
        }

    @property
    def serialize_children(self):
       return [item.serialize for item in self.items]


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String, index=True)
    description = Column(Text)
    category = Column(Integer, ForeignKey('category.id'))
    date_added = Column(DateTime, default=datetime.datetime.utcnow)
    creator_id = Column(Integer, ForeignKey('user.id'))

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        'id' : self.id,
        'name' : self.name,
        'description' : self.description,
        'date_added' : self.date_added,
        'creator_id' : self.creator_id
        }


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
