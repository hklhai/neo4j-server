# -*- coding: utf-8 -*-

import hashlib

m = hashlib.md5()  # 创建md5对象
m.update('abcdefg'.encode('utf-8'))  # 生成加密串，其中password是要加密的字符串
print(m.hexdigest())  # 打印经过md5加密的字符串

m.update('123456'.encode('utf-8'))  # 生成加密串，其中password是要加密的字符串
print(m.hexdigest())  # 打印经过md5加密的字符串
