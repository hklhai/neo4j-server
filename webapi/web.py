# -*- coding: utf-8 -*-
import json
import os
import sys
from datetime import datetime
from functools import wraps
from itertools import groupby
from operator import itemgetter

from elasticsearch import Elasticsearch
from flask import Flask, make_response
from flask import abort
from flask import request, jsonify, flash
from flask_bootstrap import Bootstrap
from flask_cors import CORS
from flask_login import LoginManager
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from py2neo import Graph, Node, Relationship, NodeSelector
from werkzeug.contrib.fixers import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

sys.path.append(os.path.dirname(os.getcwd()))

from common.global_list import *
from webapi.webapimodels import new_alchemy_encoder, Work, Book, User, VBook

app = Flask(__name__)

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
def add_book():
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
    category = request.get_json().get('category')
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


@app.route('/api/book/complet/edelete', methods=['POST'])
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
        return jsonify({'code': 1, 'message': '删除小说成功'})
    else:
        db.session.close()
        return jsonify({'code': 0, 'message': '删除小说失败'})


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
    book = Book.query.filter_by(bookid=bookid, booklabel=0).first()
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
        all_doc = es.search(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=query)
        return jsonify({'code': 1, 'next_chapter': len(all_doc['hits']['hits']) + 1})
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
                selector = NodeSelector(character_graph)
                extract_realtion_persist_to_neo4j(eid, peoples, selector)
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
            selector = NodeSelector(character_graph)
            extract_realtion_persist_to_neo4j(eid, peoples, selector)
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


def extract_realtion_persist_to_neo4j(eid, peoples, selector):
    """
    抽取json关系持久化至Neo4j

    :param eid: 保存小说整体信息eid
    :param peoples: 人物设定json
    :param selector:  neo4j selector
    """
    for j in range(len(peoples)):
        node_name = peoples[j]['name']
        node_list = selector.select("Person", name=node_name, eid=eid)
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
                find_code = character_graph.find_one(label="Person", property_key="name",
                                                     property_value=relation['being'])
                if find_code is None:
                    node2 = Node("Person", name=relation['being'], eid=eid, image="PERSON.PNG")
                    character_graph.create(node2)
                    node_call_node_2 = Relationship(node, relation['realtion'], node2)
                    node_call_node_2['edge'] = relation['realtion']
                    node_call_node_2['eid'] = eid
                    character_graph.create(node_call_node_2)
                else:
                    node_call_node_2 = Relationship(node, relation['realtion'], find_code)
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
                find_code = character_graph.find_one(label="Person", property_key="name",
                                                     property_value=relation['being'])
                if find_code is None:
                    node2 = Node("Person", name=relation['being'], eid=eid, image="PERSON.PNG")
                    character_graph.create(node2)
                    node_call_node_2 = Relationship(node, relation['realtion'], node2)
                    node_call_node_2['edge'] = relation['realtion']
                    node_call_node_2['eid'] = eid
                    character_graph.create(node_call_node_2)
                else:
                    node_call_node_2 = Relationship(node, relation['realtion'], find_code)
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
        # query = {'query': {'term': {'search_text': search_text}}, "from": page_index, "size": page_size,
        #          "highlight": {"fields": {"search_text": {}}}}

        query = {'query': {'match': {'search_text': search_text}}, "from": page_index, "size": page_size,
                 "highlight": {"fields": {"search_text": {}}}}
        query_total = {'query': {'match': {'search_text': search_text}}}
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

"""  ========================================人工智能模拟 开始================================================== """


@app.route('/api/ai', methods=['POST'])
@allow_cross_domain
def ai():
    """
    {
        "guideTopic": "你最近身体如何",
        "topicTraction": ["那你要赶紧去好好查查", "那你要赶紧去好好查查"],
        "innovation": 1,
        "lineNum": 100,
        "model": [
            "A", "B"
        ]
    }
    """
    if not request.json or 'model' not in request.json:
        abort(400)
    model = request.get_json().get('model')
    guide_topic = request.get_json().get('guideTopic')
    topic_traction = request.get_json().get('topicTraction')
    innovation = request.get_json().get('innovation')
    line_num = request.get_json().get('lineNum')
    print(model)
    print(guide_topic)
    print(topic_traction)
    print(innovation)
    print(line_num)
    return jsonify({"text": "生成文本"})


"""  ========================================人工智能模拟 结束================================================== """


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
