# -*- coding: utf-8 -*-


import jieba.analyse

sentence = '全国港澳研究会会长徐泽在会上发言指出，学习系列重要讲话要深刻领会 主席关于香港回归后的宪制基础和宪制秩序的论述，这是过去20年特别是中共十八大以来"一国两制"在香港实践取得成功的根本经验。首先，要在夯实 香港的宪制基础、巩固香港的宪制秩序上着力。只有牢牢确立起"一国两制"的宪制秩序，才能保证"一国两制"实践不走样 、不变形。其次，要在完善基本法实施的制度和机制上用功。中央直接行使的权力和特区高度自治权的结合是特区宪制秩 序不可或缺的两个方面，同时必须切实建立以行政长官为核心的行政主导体制。第三，要切实加强香港社会特别是针对公 职人员和青少年的宪法、基本法宣传，牢固树立"一国"意识，坚守"一国"原则。第四，要努力在全社会形成聚焦发展、抵 制泛政治化的氛围和势能，全面准确理解和落实基本法有关经济事务的规定，使香港继续在国家发展中发挥独特作用并由 此让最广大民众获得更实在的利益。'

keywords = jieba.analyse.extract_tags(sentence, topK=5, withWeight=True, allowPOS=('n', 'nr', 'ns'))

for item in keywords:
    print(item[0], item[1])

print("============")
keywords = jieba.analyse.extract_tags(sentence, topK=20, withWeight=True, allowPOS=('n', 'nr', 'ns'))
for item in keywords:
    print(item[0], item[1])
