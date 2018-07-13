# -*- coding: utf-8 -*-
from elasticsearch import Elasticsearch


def export():
    es = Elasticsearch(["spark3:9200"])
    index_name = "search_text"
    type_name = "text"
    target_index_name = "search_text"
    file_name = "D:\search_text.json"

    count = es.count(index=index_name, doc_type=type_name)['count']
    body = {"size": count}
    data = es.search(index=index_name, doc_type=type_name, body=body)['hits']['hits']

    tmp = ""
    for i in range(len(data) - 1):
        index = "{\"index\":{\"_index\":\"" + target_index_name + "\",\"_id\":" + str(i) + "}}\n"
        tmp += index
        tmp += str(data[i]['_source'])
        tmp += "\n"


if __name__ == '__main__':
    """
    curl -H "Content-Type: application/x-ndjson" -XPOST "spark3:9200/film_data/film/_bulk?pretty" --data-binary @film_data.json
    """
    export()
