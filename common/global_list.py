# -*- coding: utf-8 -*-
import base64

from Crypto.Cipher import AES

# DEV_MODE = "DEBUG"
DEV_MODE = "FML"

if DEV_MODE == "DEBUG":
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://srwc:mysql@ubuntu1/srwc"
    # ElasticSearch
    HOST_PORT = 'ubuntu1:9200'

    # Neo4j Knowledge Graph
    NEO4J_HOST = "ubuntu1"
    # Neo4j Character Setting
    CHARACTER_NEO4J_HOST = "ubuntu3"
else:
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://srwc:mysql@localhost/srwc"
    # ElasticSearch
    HOST_PORT = 'spark3:9200'

    # Neo4j Knowledge Graph
    NEO4J_HOST = "spark1"
    # Neo4j Character Setting
    CHARACTER_NEO4J_HOST = "spark3"

# Neo4j Knowledge Graph
NEO4J_HTTP_PORT = 7474
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "srwc"

# Neo4j Character Setting
CHARACTER_NEO4J_HTTP_PORT = 7474
CHARACTER_NEO4J_USER = "neo4j"
CHARACTER_NEO4J_PASSWORD = "srwc"

# ElasticSearch index
NEWS_INDEX = "news_data"
NEWS_TYPE = "news"

CHAPTER_INDEX = "chapter_data"
CHAPTER_TYPE = "chapter"

BOOK_INDEX = "book_info"
BOOK_TYPE = "book"

CHARACTER_INDEX = "character_info"
CHARACTER_TYPE = "character"

SEARCH_TEXT_INDEX = "search_text"
SEARCH_TEXT_TYPE = "text"

# 电视剧场次
SCENE_INDEX = "scene_data"
SCENE_TYPE = "scene"

# 评论数据
COMMENT_INDEX = "news_comment"
COMMENT_TYPE = "comment"

# 用户搜索日志
USER_SEARCH_INDEX = "user_search"
USER_SEARCH_TYPE = "search"

mode = AES.MODE_CBC
key = 'keyskeyskeyskeys'
iv = '1234567890123456'
PADDING = '\0'


def encrypt(source):
    # str = 'y+BjjfXVZJ2f+ZYoljpJdw=='
    pad_it = lambda s: s + (16 - len(s) % 16) * PADDING
    # source = 'admin'
    generator = AES.new(key, AES.MODE_CBC, iv)
    crypt = generator.encrypt(pad_it(source))
    crypted_string = base64.b64encode(crypt)
    return crypted_string


def decrypt(crypt):
    # 先转成字节数组
    b = bytes(crypt, encoding='utf-8')
    # base64解密
    base = base64.b64decode(crypt)
    generator = AES.new(key, AES.MODE_CBC, iv)
    recovery = generator.decrypt(base)
    orgin = str(recovery, encoding='utf-8')
    return orgin.rstrip(PADDING)
