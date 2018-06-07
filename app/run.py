# -*- coding: utf-8 -*-
from flask import Flask, render_template, flash, url_for, redirect, Blueprint
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from common.global_list import SQLALCHEMY_DATABASE_URI

app = Flask(__name__)

# 各项插件的配置

# 配置flask配置对象中键：SQLALCHEMY_DATABASE_URI
app.config.from_object('config')
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
# 配置flask配置对象中键：SQLALCHEMY_COMMIT_TEARDOWN,设置为True,应用会自动在每次请求结束后提交数据库中变动
app.config['SQLALCHEMY_COMMIT_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
db = SQLAlchemy()
db.init_app(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
login_manger = LoginManager()
login_manger.session_protection = 'strong'
login_manger.login_view = 'blog.login'
login_manger.init_app(app)


@login_manger.user_loader
def load_user(user_id):
    from app.model import User
    return User.query.get(int(user_id))


"""
蓝图注册
"""
def init():
    from app.views import blog
    app.register_blueprint(blueprint=blog, url_prefix='/')


if __name__ == '__main__':
    init()
    app.run(port=8888, debug=True)
