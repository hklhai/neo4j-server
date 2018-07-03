# -*- coding: utf-8 -*-
import json

from py2neo import Graph, Relationship, NodeSelector, Node

from common.global_list import *

json_text = """
{"people":[{"name":"孙悟空","relationship":[{"realtion":"师傅","being":"唐僧"},{"realtion":"徒弟","being":"猪八戒"},{"realtion":"师弟","being":"沙和尚"}],"characters":"活泼开朗","titles":"大师兄"},{"name":"唐僧","relationship":[{"realtion":"徒弟","being":"孙悟空"},{"realtion":"徒弟","being":"猪八戒"},{"realtion":"徒弟","being":"沙和尚"}],"characters":"老实","titles":"师傅"},{"name":"猪八戒","relationship":[{"realtion":"师傅","being":"唐僧"},{"realtion":"师兄","being":"孙悟空"},{"realtion":"师弟","being":"沙和尚"}],"characters":"贪吃","titles":"徒弟"},{"name":"沙和尚","relationship":[{"realtion":"师傅","being":"唐僧"},{"realtion":"大师兄","being":"孙悟空"},{"realtion":"二师兄","being":"猪八戒"}],"characters":"老实","titles":"徒弟"}]}
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