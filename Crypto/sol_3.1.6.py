
# WHA:
# Input{inStr: a binary string of bytes}
# Output{outHash: 32-bit hashcode for the inStr as a series of hex values}
# Mask: 0x3FFFFFFF
# outHash: 0
# for byte in input
#     intermediate_value = ((byte XOR 0xCC) Left Shift 24) OR
#                         ((byte XOR 0x33) Left Shift 16) OR
#                         ((byte XOR 0xAA) Left Shift 8) OR
#                         (byte XOR 0x55)
# outHash = (outHash AND Mask) + (intermediate_value AND Mask)
# return outHash

def WHA(inStr: str):
    outHash = 0
    mask = int('0x3FFFFFFF', 16)

    for char in inStr:
        byte = ord(char)
        intermediate_value = (((byte ^ int('0xCC', 16)) << 24) |
                             ((byte ^ int('0x33', 16)) << 16) |
                             ((byte ^ int('0xAA', 16)) << 8) |
                             ( byte ^ int('0x55', 16)))
    outHash = (outHash & mask) + (intermediate_value & mask)
    return outHash
print(WHA("Hello world!"))
assert format(WHA("Hello world!"), '#x') == '0x50b027cf'
assert format(WHA("I am Groot."), '#x') == '0x57293cbb'

print("Passed tests")
