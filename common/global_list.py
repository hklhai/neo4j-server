# -*- coding: utf-8 -*-

# MYSQL
SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:mysql@spark1/srwc"

# ElasticSearch
HOST_PORT = 'spark3:9200'

# ElasticSearch index
NEWS_INDEX = "news_data"
NEWS_TYPE = "news"


CHAPTER_INDEX = "chapter_data"
CHAPTER_TYPE = "chapter"

# Neo4j
# NEO4J_HOST = "127.0.0.1"
NEO4J_HOST = "spark1"
NEO4J_HTTP_PORT = 7474
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "srwc"
