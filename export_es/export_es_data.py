# -*- coding: utf-8 -*-

"""

/**
 * curl -H "Content-Type: application/x-ndjson" -XPOST "spark3:9200/film_data/film/_bulk?pretty" --data-binary @film_data.json
 * <p>
 * 如果提示 Result window is too large
 */
@Override
public void export() {
    SearchResponse response = client.prepareSearch("market_book")
            .setTypes("book").setQuery(QueryBuilders.matchAllQuery())
            .execute().actionGet();
    SearchHits resultHits = response.getHits();

    Long totalHits = resultHits.totalHits;
    response = client.prepareSearch("market_book")
            .setTypes("book").setQuery(QueryBuilders.matchAllQuery()).setFrom(0).setSize(totalHits.intValue())
            .execute().actionGet();
    resultHits = response.getHits();

    StringBuilder stringBuilder = new StringBuilder(128214);
    for (int i = 0; i < resultHits.getHits().length; i++) {
        String jsonStr = resultHits.getHits()[i].getSourceAsString();

        String index = "{\"index\":{\"_index\":\"market_book2\",\"_id\":" + i + "}}\n";
        stringBuilder.append(index);
        stringBuilder.append(jsonStr).append("\n");
    }
    String fileName = "d:\\film_data.json";
    FileUtils.writeStrToFile(stringBuilder.toString(), fileName);
}
"""
import json
import os
import time
import urllib


class exportEsData():
    size = 10000

    def __init__(self, url, index, type):
        self.url = url + "/" + index + "/" + type + "/_search"
        self.index = index
        self.type = type

    def exportData(self):
        print("export data begin...")
        begin = time.time()
        try:
            os.remove(self.index + "_" + self.type + ".json")
        except:
            os.mknod(self.index + "_" + self.type + ".json")
        msg = urllib.request.urlopen(self.url).read()
        print(msg)
        obj = json.loads(msg)
        num = obj["hits"]["total"]
        start = 0
        end = num / self.size + 1
        while (start < end):
            msg = urllib.request.urlopen(
                self.url + "?from=" + str(start * self.size) + "&size=" + str(self.size)).read()
            self.writeFile(msg)
            start = start + 1
        print("export data end!!!\n\t total consuming time:" + str(time.time() - begin) + "s")

    def writeFile(self, msg):
        obj = json.loads(msg)
        vals = obj["hits"]["hits"]
        try:
            f = open(self.index + "_" + self.type + ".json", "a")
            for val in vals:
                a = json.dumps(val["_source"], ensure_ascii=False)
                f.write(a + "\n")
        finally:
            f.flush()
            f.close()


class importEsData():
    def __init__(self, url, index, type):
        self.url = url + "/" + index + "/" + type
        self.index = index
        self.type = type

    def importData(self):
        print("import data begin...")
        begin = time.time()
        try:
            f = open(self.index + "_" + self.type + ".json", "r")
            for line in f:
                self.post(line)
        finally:
            f.close()
        print("import data end!!!\n\t total consuming time:" + str(time.time() - begin) + "s")

    def post(self, data):
        req = urllib.request.Request(self.url, data, {"Content-Type": "application/json; charset=UTF-8"})
        urllib.request.urlopen(req)


if __name__ == '__main__':
    '''
        Export Data
        e.g.
                            URL                    index        type
        exportEsData("http://10.100.142.60:9200","watchdog","mexception").exportData()

        export file name: watchdog_mexception.json
    '''
    # exportEsData("http://spark3:9200", "chapter_data", "chapter").exportData()
    exportEsData("http://spark3:9200", "news_data", "news").exportData()


    '''
        Import Data

        *import file name:watchdog_test.json    (important)
                    "_" front part represents the elasticsearch index
                    "_" after part represents the  elasticsearch type
        e.g.
                            URL                    index        type
        mportEsData("http://10.100.142.60:9200","watchdog","test").importData()
    '''
    # importEsData("http://10.100.142.60:9200","watchdog","test").importData()
    # importEsData("http://10.100.142.60:9200", "watchdog", "test").importData()
