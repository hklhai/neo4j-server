# -*- coding: utf-8 -*-

import os
import sys

sys.path.append(os.path.dirname(os.getcwd()))
from common.utils import Crypt

pc = Crypt('keyskeyskeyskeys')  # 初始化密钥
e = pc.encrypt("12345600")
d = pc.decrypt(e)
print(e, d)