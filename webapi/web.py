# -*- coding: utf-8 -*-
import hashlib
import time

from flask import Flask, make_response
from flask import request, jsonify, flash
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_login import login_user
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from flask import abort

from app.model import User
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


@app.route('/api/login', methods=['POST'])
def login():
    username = request.get_json().get('username')
    password = request.get_json().get('password')
    user = User.query.filter_by(username=username).first()
    if user is not None and check_password_hash(user.password, password):
        return jsonify({'code': 1, 'message': '成功登录', 'username': user.username})
    else:
        flash('用户或密码错误')
        return jsonify({'code': 0, 'message': '用户名或密码错误'})


@app.route('/api/register', methods=['POST'])
def register():
    if not request.json or not 'username' in request.json:
        abort(400)

    username = request.get_json().get('username')
    user = User.query.filter_by(username=username).first()
    if user is not None:
        return jsonify({'code': 0, 'message': '用户名已存在！'})

    user = User(username=username,
                password=generate_password_hash(request.get_json().get('password')))
    db.session.add(user)
    db.session.commit()
    return jsonify({'code': 1, 'message': '注册成功'})


tasks = [{'id': 1, 'title': u'Buy groceries', 'description': u'Milk, Cheese, Pizza, Fruit, Tylenol', 'done': False}]


@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    return jsonify({'tasks': tasks})


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8888, debug=True)
