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
from werkzeug.security import check_password_hash, generate_password_hash

sys.path.append(os.path.dirname(os.getcwd()))

from common.global_list import *
from webapi.webapimodels import new_alchemy_encoder, Work

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
    from app.model import User
    return User.query.get(int(user_id))


@app.route('/', methods=['GET'])
@allow_cross_domain
def index():
    return jsonify({'code': 1, 'message': 'SRWC-Server Started'})


"""  ========================================登录注册管理 结束================================================== """


@app.route('/api/work/save', methods=['POST'])
@allow_cross_domain
def work_save():
    """
    保存工作区信息，存在userid更新保存，不存爱userid新增保存
    """""
    if not request.json or not 'userid' in request.json or not "eid" in request.json:
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
    if not request.json or not 'username' in request.json or not "password" in request.json:
        abort(400)
    username = request.get_json().get('username')
    password = request.get_json().get('password')
    from webapi.webapimodels import User
    user = db.session.query(User).filter_by(username=username).first()

    db.session.close()
    if user is not None and check_password_hash(user.password, password):
        return jsonify({'code': 1, 'message': '成功登录', 'username': user.username, 'userid': user.uid})
    else:
        flash('用户或密码错误')
        return jsonify({'code': 0, 'message': '用户名或密码错误'})


@app.route('/api/work/detail', methods=['POST'])
@allow_cross_domain
def work_detail():
    """
    查询工作信息
    :return:
    """
    if not request.json or not 'userid' in request.json:
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
    if not request.json or not 'username' in request.json or not 'phonenumber' in request.json or not 'sex' in request.json:
        abort(400)

    username = request.get_json().get('username')
    phonenumber = request.get_json().get('phonenumber')
    sex = request.get_json().get('sex')
    from webapi.webapimodels import User
    user = db.session.query(User).filter_by(username=username).first()

    if user is not None:
        return jsonify({'code': 0, 'message': '用户名已存在！'})

    user = User(username=username, password=generate_password_hash(request.get_json().get('password')),
                phonenumber=phonenumber, sex=sex)
    db.session.add(user)
    db.session.commit()
    db.session.close()
    return jsonify({'code': 1, 'message': '注册成功'})


"""  ========================================登录注册管理 结束================================================== """

"""  ========================================小说信息管理 开始================================================== """


@app.route('/api/addBook', methods=['POST'])
@allow_cross_domain
def add_book():
    """
    新建小说
    :return: 新建成功 | 已经存在
    """
    if not request.json or not 'userid' in request.json or not 'bookname' in request.json or not 'category' in request.json or not 'label' in request.json or not 'abstract' in request.json or not 'writing' in request.json:
        abort(400)

    bookname = request.get_json().get('bookname')
    category = request.get_json().get('category')
    label = request.get_json().get('label')
    abstract = request.get_json().get('abstract')
    writing = request.get_json().get('writing')

    from webapi.webapimodels import Book
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
    if not request.json or not 'userid' in request.json:
        abort(400)
    userid = request.get_json().get('userid')
    page_index = request.get_json().get('page_index')
    page_size = request.get_json().get('page_size')

    from webapi.webapimodels import Book
    books = db.session.query(Book).filter_by(userid=userid, booklabel=0).order_by(Book.bookid).limit(
        page_size).offset((page_index - 1) * page_size).all()
    total = db.session.query(Book).filter_by(userid=userid, booklabel=0).count()

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
    if not request.json or not 'bookid' in request.json or not 'category' in request.json or not 'label' in request.json or not 'abstract' in request.json or not 'writing' in request.json:
        abort(400)
    bookid = request.get_json().get('bookid')
    bookname = request.get_json().get('bookname')
    bookstatus = request.get_json().get('bookstatus')
    category = request.get_json().get('category')
    label = request.get_json().get('label')
    abstract = request.get_json().get('abstract')
    writing = request.get_json().get('writing')

    from webapi.webapimodels import Book
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
    if not request.json or not 'bookid' in request.json:
        abort(400)
    bookid = request.get_json().get('bookid')
    from webapi.webapimodels import Book
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
    if not request.json or not 'bookid' in request.json:
        abort(400)
    bookid = request.get_json().get('bookid')
    from webapi.webapimodels import Book
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
    if not request.json or not 'bookid' in request.json:
        abort(400)
    bookid = request.get_json().get('bookid')
    from webapi.webapimodels import Book
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
    if not request.json or not 'eid' in request.json:
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
    if not request.json or not 'bookid' in request.json:
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
    if not request.json or not 'bookid' in request.json or not 'eid' in request.json:
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
    if not request.json or not 'bookid' in request.json:
        abort(400)

    bookid = request.get_json().get('bookid')
    page_index = request.get_json().get('page_index') - 1
    page_size = request.get_json().get('page_size')

    try:
        query = {'query': {'term': {'bookid': bookid}}, "sort": [{"chapternumber": {"order": "asc"}}],
                 "from": page_index, "size": page_size}
        query_total = {'query': {'term': {'bookid': bookid}}}
        all_doc = es.search(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=query)
        total = es.count(index=CHAPTER_INDEX, doc_type=CHAPTER_TYPE, body=query_total)
        return jsonify({"data": all_doc['hits']['hits'], "total": total['count']})
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
    if not request.json or not 'eid' in request.json:
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
    if not request.json or not 'eid' in request.json:
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
    if not request.json or not 'bookid' in request.json:
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

"""  ========================================总体信息管理 开始================================================== """


@app.route('/api/info/add', methods=['POST'])
@allow_cross_domain
def info_add():
    """
    持久化总体信息至elasticsearch
    :return:
    """
    if not request.json or not 'bookid' in request.json:
        abort(400)
    try:
        bookid = request.get_json().get('bookid')
        query = {'query': {'term': {'bookid': bookid}}}
        all_doc = es.search(index=BOOK_INDEX, doc_type=BOOK_TYPE, body=query)
        if len(all_doc['hits']['hits']) == 0:
            chapterabstract = request.get_json().get('chapterabstract')
            charactersetting = request.get_json().get('charactersetting')
            bookid = request.get_json().get('bookid')
            body = {"chapterabstract": chapterabstract, "bookid": bookid, "charactersetting": str(charactersetting)}
            result = es.index(index=BOOK_INDEX, doc_type=BOOK_TYPE, body=body)
            eid = result['_id']

            # 保存信息至Neo4J
            selector = NodeSelector(character_graph)
            setting = json.loads(str(chapterabstract))
            peoples = setting['people']
            extract_realtion_persist_to_neo4j(eid, peoples, selector)

            return jsonify({'code': 1, 'message': '新增成功', "eid": eid})
        else:
            return jsonify({'code': 0, 'message': '大纲已存在'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '新增失败'})


@app.route('/api/info/edit', methods=['POST'])
@allow_cross_domain
def info_edit():
    """
    更新ElasticSearch总体信息
    :return:
    """
    if not request.json or not 'bookid' in request.json or not 'eid' in request.json:
        abort(400)
    try:
        chapterabstract = request.get_json().get('chapterabstract')
        charactersetting = request.get_json().get('charactersetting')
        bookid = request.get_json().get('bookid')
        eid = request.get_json().get('eid')

        body = {"chapterabstract": chapterabstract, "bookid": bookid, "charactersetting": str(charactersetting)}
        es.index(index=BOOK_INDEX, doc_type=BOOK_TYPE, body=body, id=eid)

        # 先删除
        cypher = "start n=node(*) match p=(n)-[*0..3]->(b) where n.eid = \'" + eid + "\'  or b.eid = \'" + eid + "\'  delete  p "
        character_graph.run(cypher)

        # 保存信息至Neo4J
        selector = NodeSelector(character_graph)
        setting = json.loads(str(charactersetting))
        peoples = setting['people']
        extract_realtion_persist_to_neo4j(eid, peoples, selector)

        return jsonify({'code': 1, 'message': '修改成功'})

    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '修改失败'})


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
                print(peoples[j]['name'] + "：" + relation['realtion'] + ":" + relation['being'])
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

            relationship = peoples[j]['relationship']
            for relation in relationship:
                print(peoples[j]['name'] + "：" + relation['realtion'] + ":" + relation['being'])
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


@app.route('/api/info/query', methods=['POST'])
@allow_cross_domain
def info_query():
    """
    获取ElasticSearch章节列表信息
    :return:
    """
    if not request.json or not 'bookid' in request.json:
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
    删除ElasticSearch章节信息
    :return:
    """
    if not request.json or not 'eid' in request.json:
        abort(400)
    try:
        eid = request.get_json().get('eid')
        es.delete(index=BOOK_INDEX, doc_type=BOOK_TYPE, id=eid)
        return jsonify({'code': 1, 'message': '删除成功'})
    except Exception as err:
        print(err)
        return jsonify({'code': 0, 'message': '删除失败'})


@app.route('/api/info/detail', methods=['POST'])
@allow_cross_domain
def get_info_detail_by_eid():
    """
    通过eid查询章节信息
    """
    if not request.json or not 'eid' in request.json:
        abort(400)

    eid = request.get_json().get('eid')
    body = {"query": {"term": {"_id": eid}}}
    all_doc = es.search(index=BOOK_INDEX, doc_type=BOOK_TYPE, body=body)
    return jsonify(all_doc['hits']['hits'][0].get('_source'))


"""  ========================================总体信息管理 结束================================================== """

"""  ========================================知识图谱管理 开始================================================== """


@app.route('/api/graph_search', methods=['POST'])
@allow_cross_domain
def graph_search():
    """
    Neo4j图数据库
    START x=node(*) MATCH (x)-[*0..3]-(y) where x.name='AI' RETURN x,y
    :return:
    """
    if not request.json or not 'search_text' in request.json:
        abort(400)
    search_text = request.get_json().get('search_text')
    cypher = "START x=node(*) MATCH (x)<-[r]-(y) where x.name=\'" + search_text + "\' RETURN y"
    c = graph.run(cypher).data()
    if len(c) == 0:
        return jsonify({"nodes": [], "edges": []})

    event = c[0]['y']['name']
    x = graph.run("START x=node(*) MATCH (x)-[r]->(y) where x.name=\'" + event + "\'  RETURN *").data()
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
    :return:
    """
    if not request.json or not 'eid' in request.json:
        abort(400)
    eid = request.get_json().get('eid')
    x = character_graph.run(
        "START x=node(*) MATCH (x)-[r]->(y) where y.eid=\'" + eid + "\' or r.eid=\'" + eid + "\'  RETURN *").data()
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


@app.errorhandler(404)
@allow_cross_domain
def not_found(error):
    """
    404 response
    :param error:
    :return:
    """
    return make_response(jsonify({'error': 'Not found'}), 404)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8888, debug=True)
    # todo
    # app.run(host="0.0.0.0", port=8888)
