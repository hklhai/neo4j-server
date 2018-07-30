# -*- coding: utf-8 -*-
import json

json_text = """
{"people":[{"name":"乔峰","relationship":[{"realtion":"父亲","being":"萧远山"},{"realtion":"妻子","being":"阿朱"},{"realtion":"二弟","being":"虚竹"},{"realtion":"三弟","being":"段誉"}],"characters":"豪爽","titles":"大英雄"},{"name":"萧远山","relationship":[{"realtion":"儿子","being":"乔峰"}],"characters":"心狠手辣","titles":"大恶人"},{"name":"段誉","relationship":[{"realtion":"大哥","being":"乔峰"},{"realtion":"妻子","being":"王语嫣"}],"characters":"多情","titles":"大理王子"},{"name":"虚竹","relationship":[{"realtion":"大哥","being":"乔峰"}],"characters":"木讷","titles":"灵鹫宫主人"},{"name":"阿朱","relationship":[{"realtion":"丈夫","being":"乔峰"},{"realtion":"妹妹","being":"王语嫣"}],"characters":"开朗","titles":"丫鬟"}]}
"""
setting = json.loads(json_text)
peoples = setting['people']
list = []

for j in range(len(peoples)):
    characters = peoples[j]['characters'].split(",")
    people = {}
    people['name'] = peoples[j]['name']
    for i in range(len(characters)):
        people['characters'] = characters[i]
    list.append(people)

json_str = json.dumps(list)

print("jsonStr:", json_str)
