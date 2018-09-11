# -*- coding: utf-8 -*-
import datetime
import json
from datetime import datetime

from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired, BadSignature
from sqlalchemy.ext.declarative import DeclarativeMeta

from webapi.web import db
from common.global_list import SECRET_KEY


class User(UserMixin, db.Model):
    """
    Mdoel  用户信息
    """
    __tablename__ = 'tb_user'
    uid = db.Column(db.Integer, autoincrement=True, primary_key=True)
    username = db.Column(db.String(60), unique=True)
    password = db.Column(db.String(200), default="")
    phonenumber = db.Column(db.BIGINT)
    sex = db.Column(db.String(2))
    name = db.Column(db.String(60))
    address = db.Column(db.String(120))
    idcard = db.Column(db.String(18))

    def get_id(self):
        return self.uid

    def __init__(self, username, password, phonenumber, sex):
        self.username = username
        self.password = password
        self.phonenumber = phonenumber
        self.sex = sex

    def __repr__(self):
        return '<User %r>' % self.username

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def generate_auth_token(self, expiration=600):
        s = Serializer(SECRET_KEY, expires_in=expiration)
        return s.dumps({'id': self.uid})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(SECRET_KEY)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return "valid token, but expired"  # valid token, but expired
        except BadSignature:
            return "invalid token"  # invalid token
        # user = User.query.get(data['id'])
        user = db.session.query(User).get(data['id'])
        db.session.close()
        return user


class Book(db.Model):
    """
    Book Mdoel  小说信息
    """
    __tablename__ = 'tb_book'
    bookid = db.Column(db.Integer, autoincrement=True, primary_key=True)
    bookname = db.Column(db.String(255), unique=True)
    userid = db.Column(db.Integer)
    bookstatus = db.Column(db.Integer)
    createtime = db.Column(db.DateTime)
    imgurl = db.Column(db.String(60))
    booklabel = db.Column(db.Integer)
    category = db.Column(db.String(20))
    label = db.Column(db.String(20))
    abstract = db.Column(db.String(1000))
    writing = db.Column(db.String(500))
    eid = db.Column(db.String(50))
    currentedit = db.Column(db.String(255))
    episodenumber = db.Column(db.Integer)
    scenenumber = db.Column(db.Integer)

    def get_id(self):
        return self.bookid


class VBook(db.Model):
    """
    VBook Mdoel  小说试图信息
    """
    __tablename__ = 'v_book'
    bookid = db.Column(db.Integer, primary_key=True)
    bookname = db.Column(db.String(255), unique=True)
    userid = db.Column(db.Integer)
    bookstatus = db.Column(db.String(30))
    createtime = db.Column(db.DateTime)
    imgurl = db.Column(db.String(60))
    booklabel = db.Column(db.Integer)
    category = db.Column(db.String(20))
    label = db.Column(db.String(20))
    abstract = db.Column(db.String(1000))
    writing = db.Column(db.String(500))
    eid = db.Column(db.String(50))
    currentedit = db.Column(db.String(255))
    episodenumber = db.Column(db.Integer)
    scenenumber = db.Column(db.Integer)

    def get_id(self):
        return self.bookid


class Work(db.Model):
    """
    Work Mdoel 保存工作台信息
    """
    __tablename__ = 'tb_work'
    wid = db.Column(db.Integer, autoincrement=True, primary_key=True)
    workmodule = db.Column(db.String(255), unique=True)
    userid = db.Column(db.Integer)
    eid = db.Column(db.String(120))
    dellabel = db.Column(db.Integer)
    bookname = db.Column(db.String(100))

    def get_id(self):
        return self.wid


class Episode(db.Model):
    """
    Episode Mdoel 章节信息
    """
    __tablename__ = 'tb_episode'
    episodeid = db.Column(db.Integer, autoincrement=True, primary_key=True)
    episodename = db.Column(db.String(255), unique=True)
    episodenumber = db.Column(db.Integer)
    bookid = db.Column(db.Integer)

    def get_id(self):
        return self.wid


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
                              not x.startswith('_') and not x.startswith("is_") and not x.startswith("passwor") and
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
