# -*- coding: utf-8 -*-
import datetime
import json
from datetime import datetime

from flask_login import UserMixin
from sqlalchemy.ext.declarative import DeclarativeMeta

from app.run import db


class User(UserMixin, db.Model):
    """
    Mdoel
    """
    __tablename__ = 'tb_user'
    uid = db.Column(db.Integer, autoincrement=True, primary_key=True)
    username = db.Column(db.String(60), unique=True)
    password = db.Column(db.String(200), default="")

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def get_id(self):
        return self.uid

    def __repr__(self):
        return '<User %r>' % self.username

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False


class Book(db.Model):
    """
    Book Mdoel
    """
    __tablename__ = 'tb_book'
    bookid = db.Column(db.Integer, autoincrement=True, primary_key=True)
    bookname = db.Column(db.String(255), unique=True)
    userid = db.Column(db.Integer)
    bookstatus = db.Column(db.Integer)
    createtime = db.Column(db.DateTime)

    def get_id(self):
        return self.bookid


def new_alchemy_encoder():
    _visited_objs = []

    class AlchemyEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj.__class__, DeclarativeMeta):
                # don't re-visit self
                if obj in _visited_objs:
                    return None
                _visited_objs.append(obj)

                # an SQLAlchemy class
                fields = {}
                for field in [x for x in dir(obj) if
                              not x.startswith('_') and not x.startswith("is_") and
                              not x.startswith("get_") and not x.startswith("query") and x != 'metadata']:
                    data = obj.__getattribute__(field)
                    try:
                        if isinstance(data, datetime):
                            data = data.strftime('%Y-%m-%d %H:%M:%S')
                        json.dumps(data)  # this will fail on non-encodable values, like other classes
                        fields[field] = data
                    except TypeError:
                        fields[field] = None
                return fields

            return json.JSONEncoder.default(self, obj)

    return AlchemyEncoder
