# -*- coding: utf-8 -*-


# DEV_MODE = "DEBUG"
DEV_MODE = "FML"

if DEV_MODE == "DEBUG":
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:mysql@spark1/srwc"
else:
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://srwc:mysql@localhost/srwc"

# ElasticSearch
HOST_PORT = 'spark3:9200'

# ElasticSearch index
NEWS_INDEX = "news_data"
NEWS_TYPE = "news"

CHAPTER_INDEX = "chapter_data"
CHAPTER_TYPE = "chapter"

BOOK_INDEX = "book_info"
BOOK_TYPE = "book"

SEARCH_TEXT_INDEX = "search_text"
SEARCH_TEXT_TYPE = "text"

# Neo4j Knowledge Graph
# NEO4J_HOST = "127.0.0.1"
NEO4J_HOST = "spark1"
NEO4J_HTTP_PORT = 7474
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "srwc"

# Neo4j Character Setting
CHARACTER_NEO4J_HOST = "spark3"
CHARACTER_NEO4J_HTTP_PORT = 7474
CHARACTER_NEO4J_USER = "neo4j"
CHARACTER_NEO4J_PASSWORD = "srwc"
