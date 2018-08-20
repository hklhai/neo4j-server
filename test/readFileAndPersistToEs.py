# -*- coding: utf-8 -*-
import json

from elasticsearch import Elasticsearch

from common.global_list import NEWS_INDEX, NEWS_TYPE

es = Elasticsearch(["ubuntu1:9200"])

linux_path = "/home/hadoop/news/2018-08-19"
dic_list = [json.loads(line) for line in open(linux_path)]
for x in dic_list:
    print(x['title'], x['create_date'], x['url'], x['url_object_id'], x['content'])
    query_total = {'query': {'match_phrase': {'title': x['title']}}}
    total = es.count(index=NEWS_INDEX, doc_type=NEWS_TYPE, body=query_total)
    if total['count'] == 0:
        body = {"title": x['title'], "create_date": x['create_date'], "url": x['url'],
                "url_object_id": x['url_object_id'], "content": x['content']}
        es.index(index=NEWS_INDEX, doc_type=NEWS_TYPE, body=body, id=None)
