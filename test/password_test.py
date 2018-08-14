# -*- coding: utf-8 -*-
import base64

from Crypto.Cipher import AES

PADDING = '\0'
# PADDING = ' '
pad_it = lambda s: s + (16 - len(s) % 16) * PADDING
key = 'keyskeyskeyskeys'
iv = '1234567890123456'
source = 'admin'
generator = AES.new(key, AES.MODE_CBC, iv)
crypt = generator.encrypt(pad_it(source))
cryptedStr = base64.b64encode(crypt)
print(cryptedStr)

generator = AES.new(key, AES.MODE_CBC, iv)
recovery = generator.decrypt(crypt)
orgin=str(recovery, encoding='utf-8')
print(orgin.rstrip(PADDING))


str = 'y+BjjfXVZJ2f+ZYoljpJdw=='
b = bytes(str, encoding='utf-8')
print(b)