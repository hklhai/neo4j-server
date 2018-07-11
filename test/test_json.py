# -*- coding: utf-8 -*-
import json

from py2neo import Graph, Relationship, NodeSelector, Node

from common.global_list import *

json_text = """
{"people":[{"name":"乔峰","relationship":[{"realtion":"父亲","being":"萧远山"},{"realtion":"妻子","being":"阿朱"},{"realtion":"二弟","being":"虚竹"},{"realtion":"三弟","being":"段誉"}],"characters":"豪爽","titles":"大英雄"},{"name":"萧远山","relationship":[{"realtion":"儿子","being":"乔峰"}],"characters":"心狠手辣","titles":"大恶人"},{"name":"段誉","relationship":[{"realtion":"大哥","being":"乔峰"},{"realtion":"妻子","being":"王语嫣"}],"characters":"多情","titles":"大理王子"},{"name":"虚竹","relationship":[{"realtion":"大哥","being":"乔峰"}],"characters":"木讷","titles":"灵鹫宫主人"},{"name":"阿朱","relationship":[{"realtion":"丈夫","being":"乔峰"},{"realtion":"妹妹","being":"王语嫣"}],"characters":"开朗","titles":"丫鬟"}]}
"""
setting = json.loads(json_text)
peoples = setting['people']
print(setting['people'])
# Neo4j Character Setting
character_graph = Graph(
    host=CHARACTER_NEO4J_HOST,
    http_port=CHARACTER_NEO4J_HTTP_PORT,
    user=CHARACTER_NEO4J_USER,
    password=CHARACTER_NEO4J_PASSWORD
)
selector = NodeSelector(character_graph)

for j in range(len(peoples)):
    """
    1.  设置人物属性
    2.  设置人物关系，需要查明是否存在实体，存在就与现有实体建立关系；不存建立实体
    """
    print(peoples[j]['name'])
    titles = peoples[j]['titles'].split(",")
    for i in range(len(titles)):
        print("title:" + titles[i])

    characters = peoples[j]['characters'].split(",")
    for i in range(len(characters)):
        print("characters:" + characters[i])

    relationship = peoples[j]['relationship']
    for relation in relationship:
        print(peoples[j]['name'] + "：" + relation['realtion'] + ":" + relation['being'])

    print('==============')

eid = "xxxxxxx"
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
            # 先判断节点是否存在
            find_code = character_graph.find_one(label="Person", property_key="name", property_value=relation['being'])
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
            print(peoples[j]['name'] + "：" + relation['realtion'] + ":" + relation['being'])
            # 先判断节点是否存在
            find_code = character_graph.find_one(label="Person", property_key="name", property_value=relation['being'])
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