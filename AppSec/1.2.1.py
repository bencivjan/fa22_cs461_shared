#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b'bcivjan2' + b'\x00'*2 + b'A+\x00')
