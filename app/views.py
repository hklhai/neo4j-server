# -*- coding: utf-8 -*-
from werkzeug.security import generate_password_hash, check_password_hash

from app.form import LoginForm, RegisterForm
from app.model import User
from app.run import db

__author__ = 'Ocean Lin'

from flask import render_template, Blueprint, redirect, url_for, flash
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required

blog = Blueprint('blog', __name__)  # 蓝图


@blog.route('/')
def index():
    form = LoginForm()
    return render_template("login.html", form=form)


@blog.route('/index')
def l_index():
    form = LoginForm()
    return render_template('login.html', form=form)


@blog.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('登录成功')
            return render_template('ok.html', name=form.username.data)
        else:
            flash('用户或密码错误')
            return render_template('login.html', form=form)


# 用户登出
@blog.route('/logout')
@login_required
def logout():
    logout_user()
    flash('你已退出登录')
    return redirect(url_for('blog.index'))


@blog.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, password=generate_password_hash(form.password.data))
        db.session.add(user)
        db.session.commit()
        flash('注册成功')
        return redirect(url_for('blog.index'))
    return render_template('register.html', form=form)
