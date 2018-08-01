# -*- coding: utf-8 -*-
import json
import os
import sys
from datetime import datetime
from functools import wraps
from itertools import groupby
from operator import itemgetter

import jieba.analyse
from elasticsearch import Elasticsearch
from flask import Flask, make_response
from flask import abort
from flask import request, jsonify, flash
from flask_bootstrap import Bootstrap
from flask_cors import CORS
from flask_httpauth import HTTPTokenAuth
from flask_login import LoginManager
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from py2neo import Graph, Node, Relationship, NodeMatcher
from werkzeug.contrib.fixers import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

sys.path.append(os.path.dirname(os.getcwd()))

from common.global_list import *
from webapi.webapimodels import new_alchemy_encoder, Work, Book, User, VBook, Episode

app = Flask(__name__)
auth = HTTPTokenAuth(scheme='Bearer')

# 配置flask配置对象中键：SQLALCHEMY_DATABASE_URI
app.config.from_object('config')
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
# 配置flask配置对象中键：SQLALCHEMY_COMMIT_TEARDOWN,设置为True,应用会自动在每次请求结束后提交数据库中变动
# app.config['SQLALCHEMY_COMMIT_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

CORS(app, supports_credentials=True)

db = SQLAlchemy(app)
db.init_app(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
login_manger = LoginManager()
login_manger.session_protection = 'strong'
login_manger.init_app(app)

# ElasticSearch Setting
es = Elasticsearch([HOST_PORT])

# Neo4j knowledge graph
graph = Graph(
    host=NEO4J_HOST,  # neo4j 搭载服务器的ip地址，ifconfig可获取到
    http_port=NEO4J_HTTP_PORT,  # neo4j 服务器监听的端口号
    user=NEO4J_USER,  # 数据库user name，如果没有更改过，应该是neo4j
    password=NEO4J_PASSWORD  # 自己设定的密码
)
#
# Neo4j Character Setting
character_graph = Graph(
    host=CHARACTER_NEO4J_HOST,
    http_port=CHARACTER_NEO4J_HTTP_PORT,
    user=CHARACTER_NEO4J_USER,
    password=CHARACTER_NEO4J_PASSWORD
)

category_dict = {"剧本": "scripts", "小说": "fiction", "电视剧": "soap opera"}
status_dict = {"未完成": 0, "已完成": 1}


def allow_cross_domain(fun):
    @wraps(fun)
    def wrapper_fun(*args, **kwargs):
        rst = make_response(fun(*args, **kwargs))
        rst.headers['Access-Control-Allow-Origin'] = '*'
        # rst.headers['Access-Control-Allow-Methods'] = 'PUT,GET,POST,DELETE'
        # allow_headers = "Referer,Accept,Origin,User-Agent"
        # rst.headers['Access-Control-Allow-Headers'] = allow_headers
        return rst

    return wrapper_fun


@login_manger.user_loader
@allow_cross_domain
def load_user(user_id):
    # from app.model import User
    # return User.query.get(int(user_id))
    return db.session.query(User).get(int(user_id))


@app.route('/', methods=['GET'])
@allow_cross_domain
def index():
    return jsonify({'code': 1, 'message': 'SRWC-Server Started'})


"""  ========================================用户信息管理 开始================================================== """


@app.route('/api/work/save', methods=['POST'])
@allow_cross_domain
def work_save():
    """
    保存工作区信息，存在userid更新保存，不存爱userid新增保存
    """""
    if not request.json or 'userid' not in request.json or "eid" not in request.json:
        abort(400)
    eid = request.get_json().get('eid')
    userid = request.get_json().get('userid')
    dellabel = 0
    workmodule = "editer"
    work = db.session.query(Work).filter_by(userid=userid, dellabel=0).first()
    if work is not None:
        work.userid = userid
        work.eid = eid
        db.session.merge(work)
        db.session.flush()
        db.session.commit()
        db.session.close()
        return jsonify({'code': 1, 'message': '保存成功'})
    else:
        work = Work(userid=userid, eid=eid, dellabel=dellabel, workmodule=workmodule)
        db.session.add(work)
        db.session.commit()
        db.session.close()
        return jsonify({'code': 1, 'message': '新增成功'})


@app.route('/api/login', methods=['POST'])
@allow_cross_domain
def login():
    """
    登录
    """
    if not request.json or 'username' not in request.json or "password" not in request.json:
        abort(400)
    username = request.get_json().get('username')
    password = request.get_json().get('password')
    u_phonenumber = db.session.query(User).filter_by(phonenumber=username).first()
    db.session.close()

    if u_phonenumber is not None and check_password_hash(u_phonenumber.password, password):
        return jsonify({'code': 1, 'message': '成功登录', 'username': u_phonenumber.username, 'userid': u_phonenumber.uid})
    else:
        flash('用户或密码错误')
        return jsonify({'code': 0, 'message': '用户名或密码错误'})


@app.route('/api/work/detail', methods=['POST'])
@allow_cross_domain
def work_detail():
    """
    查询工作信息
    """
    if not request.json or 'userid' not in request.json:
        abort(400)
    userid = request.get_json().get('userid')
    work = db.session.query(Work).filter_by(userid=userid, dellabel=0).first()
    db.session.close()
    if work is not None:
        body = {"query": {"term": {"_id": work.eid}}}
        all_doc = es.search(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=body)
        return jsonify({'code': 1, "chapter": all_doc['hits']['hits'][0].get('_source'),
                        "eid": all_doc['hits']['hits'][0]['_id']})
    else:
        return jsonify({'code': 0, 'message': '无信息！'})


@app.route('/api/register', methods=['POST'])
@allow_cross_domain
def register():
    """
    注册
    """
    if not request.json or 'username' not in request.json or 'phonenumber' not in request.json or \
            'sex' not in request.json:
        abort(400)

    username = request.get_json().get('username')
    phonenumber = request.get_json().get('phonenumber')
    sex = request.get_json().get('sex')

    if username == "":
        username = str(phonenumber)
        user = db.session.query(User).filter_by(phonenumber=phonenumber).first()
        if user is not None:
            return jsonify({'code': 0, 'message': '手机号已存在！'})
        user = db.session.query(User).filter_by(username=username).first()
        if user is not None:
            return jsonify({'code': 0, 'message': '用户名已存在！'})
    else:
        user = db.session.query(User).filter_by(username=username).first()
        if user is not None:
            return jsonify({'code': 0, 'message': '用户名已存在！'})
        user = db.session.query(User).filter_by(phonenumber=phonenumber).first()
        if user is not None:
            return jsonify({'code': 0, 'message': '手机号已存在！'})

    user = User(
        username=username,
        password=generate_password_hash(request.get_json().get('password')),
        phonenumber=phonenumber,
        sex=sex
    )

    db.session.add(user)
    db.session.commit()
    db.session.close()
    return jsonify({'code': 1, 'message': '注册成功'})


@app.route('/api/user/detail', methods=['POST'])
@allow_cross_domain
def user_detail():
    """
    用户信息获取
    """
    if not request.json or 'userid' not in request.json:
        abort(400)
    userid = request.get_json().get('userid')
    user = db.session.query(User).filter_by(uid=userid).first()
    u = json.loads(json.dumps(user, cls=new_alchemy_encoder(), check_circular=False, ensure_ascii=False))
    db.session.close()
    return jsonify({'user': u})


@app.route('/api/user/edit', methods=['POST'])
@allow_cross_domain
def user_edit():
    """
    用户信息修改
    """
    if not request.json or 'userid' not in request.json:
        abort(400)
    userid = request.get_json().get('userid')
    username = request.get_json().get('username')
    phonenumber = request.get_json().get('phonenumber')
    sex = request.get_json().get('sex')
    name = request.get_json().get('name')
    address = request.get_json().get('address')
    idcard = request.get_json().get('idcard')

    # 查询用户名是否重名
    user_username = db.session.query(User).filter_by(username=username).first()
    if user_username is not None:
        return jsonify({'code': 0, 'message': '该用户名已存在，请确认后新建！'})

    user = db.session.query(User).filter_by(uid=userid).first()
    user.username = username
    user.phonenumber = phonenumber
    user.sex = sex
    user.name = name
    user.address = address
    user.idcard = idcard

    db.session.merge(user)
    db.session.flush()
    db.session.commit()
    db.session.close()
    return jsonify({'code': 1, 'message': '修改用户信息成功'})


@app.route('/api/user/modifyPassword', methods=['POST'])
@allow_cross_domain
def user_modify_password():
    """
    用户密码修改
    """
    if not request.json or 'username' not in request.json or "password" not in request.json \
            or "newpassword" not in request.json:
        abort(400)
    username = request.get_json().get('username')
    password = request.get_json().get('password')
    newpassword = request.get_json().get('newpassword')
    u_phonenumber = db.session.query(User).filter_by(phonenumber=username).first()

    if u_phonenumber is not None and check_password_hash(u_phonenumber.password, password):
        u_phonenumber.password = generate_password_hash(newpassword)
        db.session.merge(u_phonenumber)
        db.session.flush()
        db.session.commit()
        db.session.close()
        return jsonify(
            {'code': 1, 'message': '密码修改成功', 'username': u_phonenumber.username, 'userid': u_phonenumber.uid})
    else:
        flash('用户或密码错误')
        return jsonify({'code': 0, 'message': '原密码错误！'})


"""  ========================================用户信息管理 结束================================================== """

"""  ========================================小说信息管理 开始================================================== """


@app.route('/api/addBook', methods=['POST'])
@allow_cross_domain
def book_add():
    """
    新建小说
    :return: 新建成功 | 已经存在
    """
    if not request.json or 'userid' not in request.json or 'bookname' not in request.json or \
            'category' not in request.json or 'label' not in request.json or 'abstract' not in request.json or \
            'writing' not in request.json:
        abort(400)

    bookname = request.get_json().get('bookname')
    category = request.get_json().get('category')
    label = request.get_json().get('label')
    abstract = request.get_json().get('abstract')
    writing = request.get_json().get('writing')

    book = db.session.query(Book).filter_by(bookname=bookname).first()
    if book is not None:
        return jsonify({'code': 0, 'message': '本小说已存在，请确认后新建！'})

    book = Book(
        bookname=request.get_json().get('bookname'),
        userid=request.get_json().get('userid'),
        createtime=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        category=category,
        label=label,
        abstract=abstract,
        writing=writing,
        bookstatus=0,
        booklabel=0
    )
    db.session.add(book)
    db.session.commit()
    db.session.flush()
    db.session.close()
    return jsonify({'code': 1, 'message': '新增小说成功'})


@app.route('/api/bookList', methods=['POST'])
@allow_cross_domain
def book_list():
    """
    获取当前用户图书列表
    :return: 当前用户图书列表
    """
    if not request.json or 'userid' not in request.json:
        abort(400)
    userid = request.get_json().get('userid')
    page_index = request.get_json().get('page_index')
    page_size = request.get_json().get('page_size')

    books = db.session.query(VBook).filter_by(userid=userid, booklabel=0).order_by(VBook.bookid).limit(
        page_size).offset((page_index - 1) * page_size).all()
    total = db.session.query(VBook).filter_by(userid=userid, booklabel=0).count()

    lists = json.loads(json.dumps(books, cls=new_alchemy_encoder(), check_circular=False, ensure_ascii=False))

    lists.sort(key=itemgetter('bookstatus'))
    group_by_books = groupby(lists, itemgetter('bookstatus'))
    dic = dict([(key, list(group)) for key, group in group_by_books])
    db.session.close()
    return jsonify({"books": dic, "total": total})


@app.route('/api/editBook', methods=['POST'])
@allow_cross_domain
def book_edit():
    """
    更新图书信息
    :return: 当前用户图书列表
    """
    if not request.json or 'bookid' not in request.json or 'category' not in request.json or \
            'label' not in request.json or 'abstract' not in request.json or 'writing' not in request.json:
        abort(400)
    bookid = request.get_json().get('bookid')
    bookname = request.get_json().get('bookname')
    bookstatus = request.get_json().get('bookstatus')
    category = category_dict[request.get_json().get('category')]
    label = request.get_json().get('label')
    abstract = request.get_json().get('abstract')
    writing = request.get_json().get('writing')

    book = db.session.query(Book).filter_by(bookid=bookid).first()
    if book is not None:
        book.bookname = bookname
        book.bookstatus = bookstatus
        book.category = category
        book.label = label
        book.abstract = abstract
        book.writing = writing

        db.session.merge(book)
        db.session.flush()
        db.session.commit()
        db.session.close()
        return jsonify({'code': 1, 'message': '修改小说成功'})
    else:
        db.session.close()
        return jsonify({'code': 0, 'message': '修改小说失败'})


@app.route('/api/deleteBook', methods=['POST'])
@allow_cross_domain
def book_logic_delete():
    """
    逻辑删除图书信息
    :return:
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    bookid = request.get_json().get('bookid')
    book = db.session.query(Book).filter_by(bookid=bookid).first()
    if book is not None:
        book.booklabel = 1
        db.session.merge(book)
        db.session.flush()
        db.session.commit()
        db.session.close()
        return jsonify({'code': 1, 'message': '删除小说成功'})
    else:
        db.session.close()
        return jsonify({'code': 0, 'message': '删除小说失败'})


@app.route('/api/book/complet/delete', methods=['POST'])
@allow_cross_domain
def book_complete_delete():
    """
    完全删除图书信息
    :return:
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    bookid = request.get_json().get('bookid')
    book = db.session.query(Book).filter_by(bookid=bookid).first()
    if book is not None:
        db.session.delete(book)
        db.session.commit()
        db.session.close()
        return jsonify({'code': 1, 'message': '完全删除小说成功'})
    else:
        db.session.close()
        return jsonify({'code': 0, 'message': '完全删除小说失败'})


@app.route('/api/detail', methods=['POST'])
@allow_cross_domain
def book_detail():
    """
    获取图书信息
    :return: 图书详细信息
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    bookid = request.get_json().get('bookid')
    book = db.session.query(Book).filter_by(bookid=bookid, booklabel=0).first()
    b = json.loads(json.dumps(book, cls=new_alchemy_encoder(), check_circular=False, ensure_ascii=False))
    db.session.close()
    return jsonify({"books": b})


"""  ========================================小说信息管理 结束================================================== """


@app.route('/api/news/detail', methods=['POST'])
@allow_cross_domain
def get_detail_by_eid():
    """
    通过eid查询新闻详细信息
    :return:
    """
    if not request.json or 'eid' not in request.json:
        abort(400)

    eid = request.get_json().get('eid')
    body = {"query": {"term": {"_id": eid}}}
    all_doc = es.search(index=NEWS_INDEX, doc_type=NEWS_TYPE, body=body)
    return jsonify(all_doc['hits']['hits'][0].get('_source'))


"""  ========================================章节信息管理 开始================================================== """


@app.route('/api/chapter/add', methods=['POST'])
@allow_cross_domain
def chapter_add():
    """
    持久化章节信息至elasticsearch
    :return:
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    try:
        chaptername = request.get_json().get('chaptername')
        chapterabstract = request.get_json().get('chapterabstract')
        chaptercontent = request.get_json().get('chaptercontent')
        bookid = request.get_json().get('bookid')
        chapterversion = request.get_json().get('chapterversion')
        charactersetting = request.get_json().get('charactersetting')
        chapternumber = request.get_json().get('chapternumber')
        bookname = request.get_json().get('bookname')

        create_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        edit_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        body = {"chaptername": chaptername, "chapterabstract": chapterabstract, "chaptercontent": chaptercontent,
                "bookid": bookid, "chapterversion": str(chapterversion), "charactersetting": str(charactersetting),
                "create_date": create_date, "edit_date": edit_date, "chapternumber": chapternumber,
                "bookname": bookname}

        result = es.index(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=body)
        return jsonify({'code': 1, 'message': '新增章节成功', "eid": result['_id']})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '新增章节失败'})


@app.route('/api/chapter/edit', methods=['POST'])
@allow_cross_domain
def chapter_edit():
    """
    更新ElasticSearch章节信息
    :return:
    """
    if not request.json or 'bookid' not in request.json or 'eid' not in request.json:
        abort(400)
    try:
        chaptername = request.get_json().get('chaptername')
        chapterabstract = request.get_json().get('chapterabstract')
        chaptercontent = request.get_json().get('chaptercontent')
        bookid = request.get_json().get('bookid')
        eid = request.get_json().get('eid')
        create_date = request.get_json().get('create_date')
        charactersetting = request.get_json().get('charactersetting')
        chapterversion = request.get_json().get('chapterversion')
        chapterfinish = request.get_json().get('chapterfinish')
        chapternumber = request.get_json().get('chapternumber')
        bookname = request.get_json().get('bookname')

        # 作品完稿不进入编辑页面
        if chapterfinish == 1:
            work = db.session.query(Work).filter_by(eid=eid, dellabel=0).first()
            if work is not None:
                work.dellabel = 1
                db.session.merge(work)
                db.session.flush()
                db.session.commit()
                db.session.close()

        edit_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        body = {"chaptername": chaptername, "chapterabstract": chapterabstract, "chaptercontent": chaptercontent,
                "bookid": bookid, "create_date": create_date, "edit_date": edit_date, "chapternumber": chapternumber,
                "charactersetting": str(charactersetting), "chapterversion": str(chapterversion), "bookname": bookname}
        es.index(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=body, id=eid)
        return jsonify({'code': 1, 'message': '修改章节成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '修改章节失败'})


@app.route('/api/chapter/list', methods=['POST'])
@allow_cross_domain
def chapter_list():
    """
    获取ElasticSearch章节列表信息
    :return:
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)

    bookid = request.get_json().get('bookid')
    page_index = request.get_json().get('page_index') - 1
    page_size = request.get_json().get('page_size')

    book = db.session.query(Book).filter_by(bookid=bookid).first()

    try:
        query = {'query': {'term': {'bookid': bookid}}, "sort": [{"chapternumber": {"order": "asc"}}],
                 "from": page_index, "size": page_size}
        query_total = {'query': {'term': {'bookid': bookid}}}
        all_doc = es.search(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=query)
        total = es.count(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=query_total)
        return jsonify({"data": all_doc['hits']['hits'], "total": total['count'], "description": book.abstract})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '查询失败'})


@app.route('/api/chapter/delete', methods=['POST'])
@allow_cross_domain
def chapter_delete():
    """
    删除ElasticSearch章节信息
    :return:
    """
    if not request.json or 'eid' not in request.json:
        abort(400)
    try:
        eid = request.get_json().get('eid')
        es.delete(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, id=eid)
        return jsonify({'code': 1, 'message': '删除章节成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '删除章节失败'})


@app.route('/api/chapter/detail', methods=['POST'])
@allow_cross_domain
def get_chapter_detail_by_eid():
    """
    通过eid查询章节详细信息
    """
    if not request.json or 'eid' not in request.json:
        abort(400)

    eid = request.get_json().get('eid')
    body = {"query": {"term": {"_id": eid}}}
    all_doc = es.search(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=body)
    return jsonify(all_doc['hits']['hits'][0].get('_source'))


@app.route('/api/chapter/count', methods=['POST'])
@allow_cross_domain
def chapter_count():
    """
    ElasticSearch章节数量
    :return: ElasticSearch章节数量+1
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    try:
        bookid = request.get_json().get('bookid')
        query = {'query': {'term': {'bookid': bookid}}}
        all_doc = es.count(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=query)
        return jsonify({'code': 1, 'next_chapter': all_doc['count'] + 1})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '获取失败'})


"""  ========================================章节信息管理 结束================================================== """

"""  ========================================人物设定管理 开始================================================== """


@app.route('/api/character/add', methods=['POST'])
@allow_cross_domain
def character_add():
    """
    持久化人物设定信息至elasticsearch
    :return:
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    try:
        bookid = request.get_json().get('bookid')
        query = {'query': {'term': {'bookid': bookid}}}
        all_doc = es.search(index=CHARACTER_INDEX, doc_type=CHARACTER_TYPE, body=query)
        if len(all_doc['hits']['hits']) == 0:
            charactersetting = request.get_json().get('charactersetting')
            bookid = request.get_json().get('bookid')
            body = {"bookid": bookid, "charactersetting": str(charactersetting)}
            result = es.index(index=CHARACTER_INDEX, doc_type=CHARACTER_TYPE, body=body)
            eid = result['_id']

            setting = json.loads(str(charactersetting))
            peoples = setting['people']
            # 保存信息至Neo4J
            if not len(peoples) == 0:
                matcher = NodeMatcher(character_graph)
                extract_realtion_persist_to_neo4j(eid, peoples, matcher)
            return jsonify({'code': 1, 'message': '新增成功', "eid": eid})
        else:
            return jsonify({'code': 0, 'message': '人物设定已存在'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '新增失败'})


@app.route('/api/character/edit', methods=['POST'])
@allow_cross_domain
def character_edit():
    """
    更新ElasticSearch人物设定信息
    :return:
    """
    if not request.json or 'bookid' not in request.json or 'eid' not in request.json:
        abort(400)
    try:
        charactersetting = request.get_json().get('charactersetting')
        bookid = request.get_json().get('bookid')
        eid = request.get_json().get('eid')

        body = {"bookid": bookid, "charactersetting": str(charactersetting)}
        es.index(index=CHARACTER_INDEX, doc_type=CHARACTER_TYPE, body=body, id=eid)

        # 先删除
        cypher = "start n=node(*) match p=(n)-[*0..3]->(b) where n.eid = \'" + eid + "\'  or b.eid = \'" \
                 + eid + "\'  delete  p "
        character_graph.run(cypher)

        # 保存信息至Neo4J
        setting = json.loads(str(charactersetting))
        peoples = setting['people']
        if not len(peoples) == 0:
            matcher = NodeMatcher(character_graph)
            extract_realtion_persist_to_neo4j(eid, peoples, matcher)
        return jsonify({'code': 1, 'message': '修改成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '修改失败'})


@app.route('/api/character/query', methods=['POST'])
@allow_cross_domain
def character_query():
    """
    通过bookid获取ElasticSearch人物设定信息
    :return:
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    try:
        bookid = request.get_json().get('bookid')
        query = {'query': {'term': {'bookid': bookid}}}
        all_doc = es.search(index=CHARACTER_INDEX, doc_type=CHARACTER_TYPE, body=query)
        return jsonify(all_doc['hits']['hits'])
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '查询失败'})


@app.route('/api/character/delete', methods=['POST'])
@allow_cross_domain
def character_delete():
    """
    删除ElasticSearch人物设定信息
    :return:
    """
    if not request.json or 'eid' not in request.json:
        abort(400)
    try:
        eid = request.get_json().get('eid')
        es.delete(index=CHARACTER_INDEX, doc_type=CHARACTER_TYPE, id=eid)
        return jsonify({'code': 1, 'message': '删除成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '删除失败'})


def extract_realtion_persist_to_neo4j(eid, peoples, matcher):
    """
    抽取json关系持久化至Neo4j

    :param eid: 保存小说整体信息eid
    :param peoples: 人物设定json
    :param matcher:  neo4j matcher
    """
    for j in range(len(peoples)):
        node_name = peoples[j]['name']
        node_list = matcher.match("Person", name=node_name, eid=eid)
        if len(list(node_list)) == 0:
            node = Node("Person", name=node_name, eid=eid, image="PERSON.PNG")
            titles = peoples[j]['titles'].split(",")
            for i in range(len(titles)):
                node['title'] = titles[i]

            characters = peoples[j]['characters'].split(",")
            for i in range(len(characters)):
                node['character'] = characters[i]
            character_graph.create(node)

            relationship = peoples[j]['relationship']
            for relation in relationship:
                # print(peoples[j]['name'] + "：" + relation['realtion'] + ":" + relation['being'])
                # 先判断关系节点是否存在
                match_one = matcher.match("Person", name=relation['being'], eid=eid).first()
                if match_one is None:
                    node2 = Node("Person", name=relation['being'], eid=eid, image="PERSON.PNG")
                    character_graph.create(node2)
                    node_call_node_2 = Relationship(node, relation['realtion'], node2)
                    node_call_node_2['edge'] = relation['realtion']
                    node_call_node_2['eid'] = eid
                    character_graph.create(node_call_node_2)
                else:
                    node_call_node_2 = Relationship(node, relation['realtion'], match_one)
                    node_call_node_2['edge'] = relation['realtion']
                    node_call_node_2['eid'] = eid
                    character_graph.create(node_call_node_2)
        else:
            titles = peoples[j]['titles'].split(",")
            node = list(node_list)[0]
            for i in range(len(titles)):
                node['title'] = titles[i]

            characters = peoples[j]['characters'].split(",")
            for i in range(len(characters)):
                node['character'] = characters[i]
            character_graph.push(node)

            relationship = peoples[j]['relationship']
            for relation in relationship:
                # print(peoples[j]['name'] + "：" + relation['realtion'] + ":" + relation['being'])
                # 先判断关系节点是否存在
                match_one = matcher.match("Person", name=relation['being'], eid=eid).first()
                if match_one is None:
                    node2 = Node("Person", name=relation['being'], eid=eid, image="PERSON.PNG")
                    character_graph.create(node2)
                    node_call_node_2 = Relationship(node, relation['realtion'], node2)
                    node_call_node_2['edge'] = relation['realtion']
                    node_call_node_2['eid'] = eid
                    character_graph.create(node_call_node_2)
                else:
                    node_call_node_2 = Relationship(node, relation['realtion'], match_one)
                    node_call_node_2['edge'] = relation['realtion']
                    node_call_node_2['eid'] = eid
                    character_graph.create(node_call_node_2)


"""  ========================================人物设定管理 结束================================================== """

"""  ========================================故事大纲管理 开始================================================== """


@app.route('/api/info/add', methods=['POST'])
@allow_cross_domain
def info_add():
    """
    持久化大纲信息至elasticsearch
    :return:
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    try:
        bookid = request.get_json().get('bookid')
        query = {'query': {'term': {'bookid': bookid}}}
        all_doc = es.search(index=BOOK_INDEX, doc_type=BOOK_TYPE, body=query)
        if len(all_doc['hits']['hits']) == 0:
            bookabstract = request.get_json().get('bookabstract')
            bookid = request.get_json().get('bookid')
            body = {"bookabstract": bookabstract, "bookid": bookid}
            result = es.index(index=BOOK_INDEX, doc_type=BOOK_TYPE, body=body)
            eid = result['_id']

            return jsonify({'code': 1, 'message': '新增大纲成功', "eid": eid})
        else:
            return jsonify({'code': 0, 'message': '大纲已存在'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '新增失败'})


@app.route('/api/info/edit', methods=['POST'])
@allow_cross_domain
def info_edit():
    """
    更新ElasticSearch大纲信息
    :return:
    """
    if not request.json or 'bookid' not in request.json or 'eid' not in request.json:
        abort(400)
    try:
        bookabstract = request.get_json().get('bookabstract')
        bookid = request.get_json().get('bookid')
        eid = request.get_json().get('eid')

        body = {"bookabstract": bookabstract, "bookid": bookid}
        es.index(index=BOOK_INDEX, doc_type=BOOK_TYPE, body=body, id=eid)

        # 先删除
        cypher = "start n=node(*) match p=(n)-[*0..3]->(b) where n.eid = \'" + eid + "\'  or b.eid = \'" \
                 + eid + "\'  delete  p "
        character_graph.run(cypher)

        return jsonify({'code': 1, 'message': '修改成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '修改失败'})


@app.route('/api/info/detail', methods=['POST'])
@allow_cross_domain
def get_info_detail_by_eid():
    """
    通过eid查询大纲信息
    """
    if not request.json or 'eid' not in request.json:
        abort(400)

    eid = request.get_json().get('eid')
    body = {"query": {"term": {"_id": eid}}}
    all_doc = es.search(index=BOOK_INDEX, doc_type=BOOK_TYPE, body=body)
    return jsonify(all_doc['hits']['hits'][0].get('_source'))


@app.route('/api/info/query', methods=['POST'])
@allow_cross_domain
def info_query():
    """
    通过bookid获取ElasticSearch故事大纲信息
    :return:
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    try:
        bookid = request.get_json().get('bookid')
        query = {'query': {'term': {'bookid': bookid}}}
        all_doc = es.search(index=BOOK_INDEX, doc_type=BOOK_TYPE, body=query)
        return jsonify(all_doc['hits']['hits'])
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '查询失败'})


@app.route('/api/info/delete', methods=['POST'])
@allow_cross_domain
def info_delete():
    """
    删除ElasticSearch大纲信息
    :return:
    """
    if not request.json or 'eid' not in request.json:
        abort(400)
    try:
        eid = request.get_json().get('eid')
        es.delete(index=BOOK_INDEX, doc_type=BOOK_TYPE, id=eid)
        return jsonify({'code': 1, 'message': '删除成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '删除失败'})


"""  ========================================故事大纲管理 结束================================================== """

"""  ========================================知识图谱管理 开始================================================== """


@app.route('/api/search/list', methods=['POST'])
@allow_cross_domain
def search_list():
    """
    查询命名体识别信息
    :return:
    """
    if not request.json or 'search_text' not in request.json:
        abort(400)

    search_text = request.get_json().get('search_text')
    page_index = request.get_json().get('page_index') - 1
    page_size = request.get_json().get('page_size')

    try:
        # 短语搜索match_phrase https://blog.csdn.net/cc907566076/article/details/78553950
        query = {'query': {'match_phrase': {'search_text': search_text}}, "from": page_index, "size": page_size,
                 "highlight": {"fields": {"search_text": {}}}}
        query_total = {'query': {'match_phrase': {'search_text': search_text}}}

        all_doc = es.search(index=SEARCH_TEXT_INDEX, doc_type=SEARCH_TEXT_TYPE, body=query)
        total = es.count(index=SEARCH_TEXT_INDEX, doc_type=SEARCH_TEXT_TYPE, body=query_total)
        return jsonify({"data": all_doc['hits']['hits'], "total": total['count']})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '查询失败'})


@app.route('/api/graph_search', methods=['POST'])
@allow_cross_domain
def graph_search():
    """
    Neo4j图数据库
    START x=node(*) MATCH (x)-[*0..3]-(y) where x.name='AI' RETURN x,y
    :return:
    """
    if not request.json or 'search_text' not in request.json or 'eid' not in request.json:
        abort(400)
    search_text = request.get_json().get('search_text')
    eid = request.get_json().get('eid')

    cypher = "START x=node(*) MATCH (x)<-[r]-(y) where x.name=\'" + search_text + "\' and  x.eid=\'" \
             + eid + "\' RETURN y"
    c = graph.run(cypher).data()
    if len(c) == 0:
        return jsonify({"nodes": [], "edges": []})

    event = c[0]['y']['name']
    x = graph.run("START x=node(*) MATCH (x)-[r]->(y) where x.name=\'" + event + "\'  RETURN * LIMIT 30").data()
    nodes = []
    links = []
    nodes.append(x[0].get('x'))
    for i in range(len(x)):
        nodes.append(x[i].get('y'))
        data = {'source': 0, 'target': (i + 1), 'type': x[i].get('r')['edge'], 'eid': x[i].get('y')['eid']}
        links.append(data)
    nodes = json.loads(json.dumps(nodes, cls=new_alchemy_encoder(), check_circular=False, ensure_ascii=False))
    return jsonify({"nodes": nodes, "edges": links})


"""  ========================================知识图谱管理 结束================================================== """

"""  ========================================人物设定管理 开始================================================== """


@app.route('/api/char_graph_search', methods=['POST'])
@allow_cross_domain
def char_graph_search():
    """
    人物设定查询数据接口
    """
    if not request.json or 'eid' not in request.json:
        abort(400)
    eid = request.get_json().get('eid')
    x = character_graph.run(
        "START x=node(*) MATCH (x)-[r]->(y) where y.eid=\'" + eid + "\' or r.eid=\'" + eid + "\'  RETURN * ").data()
    nodes_list = []
    nodes = []
    links = []

    # set去除重复
    for i in range(len(x)):
        nodes.append(x[i].get('x'))
        nodes.append(x[i].get('y'))

    nodes = list(set(nodes))

    for i in range(len(nodes)):
        nodes_list.append(nodes[i]['name'])

    nodes_indexes = list(range(len(nodes_list)))
    nodes_dict = dict(zip(nodes_list, nodes_indexes))

    for i in range(len(x)):
        data = {'source': nodes_dict[x[i]['x']['name']], 'target': nodes_dict[x[i]['y']['name']],
                'type': x[i].get('r')['edge'], 'eid': x[i].get('y')['eid']}
        links.append(data)
    nodes = json.loads(json.dumps(nodes, cls=new_alchemy_encoder(), check_circular=False, ensure_ascii=False))
    return jsonify({"nodes": nodes, "edges": links})


"""  ========================================人物设定管理 结束================================================== """

"""  ========================================人工智能调用 开始================================================== """


@app.route('/api/ai', methods=['POST'])
@allow_cross_domain
def ai():
    """
    根据章节信息返回主题；人物，性格
    """
    if not request.json or 'chapterabstract' not in request.json or 'bookid' not in request.json:
        abort(400)
    chapterabstract = request.get_json().get('chapterabstract')
    bookid = request.get_json().get('bookid')
    # 查询人物设定，解析并返回
    query = {'query': {'term': {'bookid': bookid}}}
    all_doc = es.search(index=CHARACTER_INDEX, doc_type=CHARACTER_TYPE, body=query)
    if len(all_doc['hits']['hits']) == 0:
        return jsonify({'code': 0, 'message': '人物设定不存在'})
    else:
        setting = json.loads(all_doc['hits']['hits'][0]['_source']['charactersetting'])
        peoples = setting['people']
        list = []

        for j in range(len(peoples)):
            if peoples[j]['name'] in chapterabstract:
                characters = peoples[j]['characters'].split(",")
                people = {}
                people['name'] = peoples[j]['name']
                for i in range(len(characters)):
                    people['characters'] = characters[i]
                list.append(people)

        keywords = jieba.analyse.extract_tags(chapterabstract, topK=5, withWeight=True, allowPOS=('n', 'nr', 'ns'))
        tags = ""
        for i in range(4):
            tags += keywords[i][0] + ","
        tag = tags[0:-1]
        return jsonify({'code': 1, 'peoples': list, 'keywords': tag})


"""  ========================================人工智能调用 结束================================================== """

"""  ========================================电视剧本管理 开始================================================== """


@app.route('/api/episode/count', methods=['POST'])
@allow_cross_domain
def episode_count():
    """
    获取电视剧剧本集数量
    :return: MySQL剧集数量+1
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    try:
        bookid = request.get_json().get('bookid')
        count = db.session.query(Episode).filter_by(bookid=bookid).count()
        return jsonify({'code': 1, 'next_episode': count + 1})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '获取失败'})


@app.route('/api/episode/add', methods=['POST'])
@allow_cross_domain
def episode_add():
    """
    持久化电视剧集数至MySQL
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    try:
        episodename = request.get_json().get('episodename')
        episodenumber = request.get_json().get('episodenumber')
        bookid = request.get_json().get('bookid')
        episode = Episode(
            episodename=episodename,
            episodenumber=episodenumber,
            bookid=bookid
        )
        db.session.add(episode)
        db.session.commit()
        db.session.flush()
        db.session.close()

        return jsonify({'code': 1, 'message': '新增剧集成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '新增剧集失败'})


@app.route('/api/episode/list', methods=['POST'])
@allow_cross_domain
def episode_list():
    """
    获取MySQL剧集列表信息
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)

    bookid = request.get_json().get('bookid')
    page_index = request.get_json().get('page_index')
    page_size = request.get_json().get('page_size')

    episodes = db.session.query(Episode).filter_by(bookid=bookid).order_by(Episode.episodenumber).limit(
        page_size).offset((page_index - 1) * page_size).all()
    total = db.session.query(Episode).filter_by(bookid=bookid).count()

    lists = json.loads(json.dumps(episodes, cls=new_alchemy_encoder(), check_circular=False, ensure_ascii=False))
    db.session.close()
    return jsonify({"episodes": lists, "total": total})


@app.route('/api/episode/edit', methods=['POST'])
@allow_cross_domain
def episode_edit():
    """
    更新MySQL中剧集信息
    """
    if not request.json or 'episodename' not in request.json or 'episodenumber' not in request.json \
            or 'episodeid' not in request.json:
        abort(400)

    episodeid = request.get_json().get('episodeid')
    episodename = request.get_json().get('episodename')
    episodenumber = request.get_json().get('episodenumber')

    episode = db.session.query(Episode).filter_by(episodeid=episodeid).first()
    if episode is not None:
        episode.episodename = episodename
        episode.episodenumber = episodenumber
        db.session.merge(episode)
        db.session.flush()
        db.session.commit()
        db.session.close()
        return jsonify({'code': 1, 'message': '修改剧集成功'})
    else:
        db.session.close()
        return jsonify({'code': 0, 'message': '修改剧集失败'})


@app.route('/api/episode/delete', methods=['POST'])
@allow_cross_domain
def episode_delete():
    """
    删除MySQL剧集信息
    :return:
    """
    if not request.json or 'episodeid' not in request.json:
        abort(400)
    episodeid = request.get_json().get('episodeid')
    episode = db.session.query(Episode).filter_by(episodeid=episodeid).first()
    if episode is not None:
        db.session.delete(episode)
        db.session.commit()
        db.session.close()
        return jsonify({'code': 1, 'message': '删除剧集成功'})
    else:
        db.session.close()
        return jsonify({'code': 0, 'message': '删除剧集失败'})


@app.route('/api/episode/detail', methods=['POST'])
@allow_cross_domain
def get_episode_detail_by_episodeid():
    """
    通过episodeid查询剧集详细信息
    """
    if not request.json or 'episodeid' not in request.json:
        abort(400)
    episodeid = request.get_json().get('episodeid')
    episode = db.session.query(Episode).filter_by(episodeid=episodeid).first()
    b = json.loads(json.dumps(episode, cls=new_alchemy_encoder(), check_circular=False, ensure_ascii=False))
    db.session.close()
    return jsonify({"episode": b})


"""  ========================================电视剧本管理 结束================================================== """

"""  ========================================电视场次管理 开始================================================== """


@app.route('/api/scene/count', methods=['POST'])
@allow_cross_domain
def scene_count():
    """
    ElasticSearch电视场数量
    :return: ElasticSearch电视场数量+1
    """
    if not request.json or 'episodeid' not in request.json or 'bookid' not in request.json:
        abort(400)
    try:
        episodeid = request.get_json().get('episodeid')
        bookid = request.get_json().get('bookid')
        # 不确定集数根据作品id查询
        if episodeid == 0:
            episode = db.session.query(Episode).filter_by(bookid=bookid).order_by(Episode.episodenumber.desc()).first()
            if episode is not None:
                # 存在去除最大集数
                episodeid = episode.episodeid
                query = {'query': {'term': {'episodeid': episodeid}}}
                all_doc = es.count(index=SCENE_INDEX, doc_type=SCENE_TYPE, body=query)
                return jsonify({'code': 1, 'next_scene': all_doc['count'] + 1})
            else:
                # 不存在为1
                return jsonify({'code': 1, 'next_scene': 1})
        else:
            query = {'query': {'term': {'episodeid': episodeid}}}
            all_doc = es.search(index=SCENE_INDEX, doc_type=SCENE_TYPE, body=query)
            return jsonify({'code': 1, 'next_scene': len(all_doc['hits']['hits']) + 1})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '获取失败'})


@app.route('/api/scene/add', methods=['POST'])
@allow_cross_domain
def scene_add():
    """
    持久化电视剧场次信息至elasticsearch
    """
    if not request.json or 'bookid' not in request.json:
        abort(400)
    try:
        scenename = request.get_json().get('scenename')
        scenecontent = request.get_json().get('scenecontent')
        bookid = request.get_json().get('bookid')
        sceneversion = request.get_json().get('sceneversion')
        charactersetting = request.get_json().get('charactersetting')
        scenenumber = request.get_json().get('scenenumber')
        bookname = request.get_json().get('bookname')
        episodeid = request.get_json().get('episodeid')

        create_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        edit_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        body = {"scenename": scenename, "scenecontent": scenecontent, "episodeid": episodeid,
                "bookid": bookid, "sceneversion": str(sceneversion), "charactersetting": str(charactersetting),
                "create_date": create_date, "edit_date": edit_date, "scenenumber": scenenumber,
                "bookname": bookname}

        result = es.index(index=SCENE_INDEX, doc_type=SCENE_TYPE, body=body)
        return jsonify({'code': 1, 'message': '新增成功', "eid": result['_id']})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '新增失败'})


@app.route('/api/scene/list', methods=['POST'])
@allow_cross_domain
def scene_list():
    """
    获取ElasticSearch电视剧场次列表信息
    :return:
    """
    if not request.json or 'bookid' not in request.json or 'episodeid' not in request.json:
        abort(400)

    bookid = request.get_json().get('bookid')
    episodeid = request.get_json().get('episodeid')
    page_index = request.get_json().get('page_index') - 1
    page_size = request.get_json().get('page_size')

    book = db.session.query(Book).filter_by(bookid=bookid).first()

    try:
        query = {'query': {'term': {'episodeid': episodeid}}, "sort": [{"scenenumber": {"order": "asc"}}],
                 "from": page_index, "size": page_size}
        query_total = {'query': {'term': {'episodeid': episodeid}}}
        all_doc = es.search(index=SCENE_INDEX, doc_type=SCENE_TYPE, body=query)
        total = es.count(index=SCENE_INDEX, doc_type=SCENE_TYPE, body=query_total)
        return jsonify({"data": all_doc['hits']['hits'], "total": total['count'], "description": book.abstract})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '查询失败'})


@app.route('/api/scene/edit', methods=['POST'])
@allow_cross_domain
def scene_edit():
    """
    更新ElasticSearch场次信息
    :return:
    """
    if not request.json or 'eid' not in request.json:
        abort(400)
    try:
        scenename = request.get_json().get('scenename')
        scenecontent = request.get_json().get('scenecontent')
        bookid = request.get_json().get('bookid')
        eid = request.get_json().get('eid')
        create_date = request.get_json().get('create_date')
        charactersetting = request.get_json().get('charactersetting')
        sceneversion = request.get_json().get('sceneversion')
        scenefinish = request.get_json().get('scenefinish')
        scenenumber = request.get_json().get('scenenumber')
        bookname = request.get_json().get('bookname')
        # 由episode_list获取
        episodeid = request.get_json().get('episodeid')

        # 作品完稿不进入编辑页面
        if scenefinish == 1:
            work = db.session.query(Work).filter_by(eid=eid, dellabel=0).first()
            if work is not None:
                work.dellabel = 1
                db.session.merge(work)
                db.session.flush()
                db.session.commit()
                db.session.close()

        edit_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        body = {"scenename": scenename, "scenecontent": scenecontent, "episodeid": episodeid,
                "bookid": bookid, "create_date": create_date, "edit_date": edit_date, "scenenumber": scenenumber,
                "charactersetting": str(charactersetting), "sceneversion": str(sceneversion), "bookname": bookname}
        es.index(index=SCENE_INDEX, doc_type=SCENE_TYPE, body=body, id=eid)
        return jsonify({'code': 1, 'message': '修改成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '修改失败'})


@app.route('/api/scene/delete', methods=['POST'])
@allow_cross_domain
def scene_delete():
    """
    删除ElasticSearch电视剧场次信息
    :return:
    """
    if not request.json or 'eid' not in request.json:
        abort(400)
    try:
        eid = request.get_json().get('eid')
        es.delete(index=SCENE_INDEX, doc_type=SCENE_TYPE, id=eid)
        return jsonify({'code': 1, 'message': '删除成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '删除失败'})


"""  ========================================电视场次管理 结束================================================== """

"""  ========================================评论数据查询 开始================================================== """


@app.route('/api/comment/search', methods=['POST'])
@allow_cross_domain
def comment_search():
    if not request.json or 'word' not in request.json:
        abort(400)

    word = request.get_json().get('word')
    page_index = request.get_json().get('page_index') - 1
    page_size = request.get_json().get('page_size')
    try:
        query = {'query': {'match_phrase': {'content': word}}, "from": page_index, "size": page_size,
                 "highlight": {"fields": {"content": {}}}}
        query_total = {'query': {'match_phrase': {'content': word}}}
        all_doc = es.search(index=COMMENT_INDEX, doc_type=COMMENT_TYPE, body=query)
        total = es.count(index=COMMENT_INDEX, doc_type=COMMENT_TYPE, body=query_total)
        return jsonify({"data": all_doc['hits']['hits'], "total": total['count']})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '查询失败'})


"""  ========================================评论数据查询 结束================================================== """


@app.errorhandler(404)
@allow_cross_domain
def not_found():
    """
    404 response
    """
    return make_response(jsonify({'error': 'Not found'}), 404)


if __name__ == '__main__':
    if DEV_MODE == "DEBUG":
        app.run(host="0.0.0.0", port=8888, debug=True)
    else:
        app.wsgi_app = ProxyFix(app.wsgi_app)
        app.run()
