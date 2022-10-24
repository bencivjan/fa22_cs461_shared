# strip() remove any leading or trailing whitespace characters
with open('3.1.1_value.hex') as f:
    file_content = f.read().strip()

integer_parsed = int(file_content, 16)
print("3.1.1_value.hex as decimal value: ", integer_parsed)

binary_parsed = bin(integer_parsed)[2:]
print("3.1.1_value.hex as binary value: ", binary_parsed)
