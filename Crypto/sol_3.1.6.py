import sys
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
#     outHash = (outHash AND Mask) + (intermediate_value AND Mask)
# return outHash

def WHA(inStr: str):
    outHash = 0
    mask = 0x3FFFFFFF

    for char in inStr:
        byte = ord(char)
        intermediate_value = (((byte ^ 0xCC) << 24) |
                             ((byte ^ 0x33) << 16) |
                             ((byte ^ 0xAA) << 8) |
                             ( byte ^ 0x55))
        outHash = (outHash & mask) + (intermediate_value & mask)
    return outHash

# assert WHA(" ") == 0x2c138a75
# assert WHA("Hello world!") == 0x50b027cf
# assert WHA("I am Groot.") == 0x57293cbb

# print("Passed tests")

# find weakness
# assert WHA("ab") == WHA("ba")
# assert WHA("Hello world!") == WHA("eHllo world!")

inFile = sys.argv[1]
outFile = sys.argv[2]
inText = ''

with open(inFile) as f:
    inText = f.read().strip()

with open(outFile, 'w') as f:
    f.write(format(WHA(inText), '#x'))
