#!/usr/bin/env python3
# -*- coding: latin-1 -*-
blob = """     OFD�A36�g@��.�R���~Ò ƃ�U��.���lBJ*���@j`t�O���%W�}]�𨮹Q�ٙ�S�ɡ�Q��ОF%��J�l�<���|z,T�����KU]��dd���(�luf"""
from hashlib import sha256
if sha256(blob.encode()).hexdigest()[0] == '4':
    print("I come in peace.")
else:
    print("Prepare to be destroyed!")