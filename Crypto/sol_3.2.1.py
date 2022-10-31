import sys
from pymd5 import md5, padding
from urllib.parse import quote_from_bytes

def length_extension(orig_hash, orig_message_len, command3):
    count = (orig_message_len + len(padding(orig_message_len*8)))*8

    h = md5(state=orig_hash, count=count)
    h.update(command3)
    return h.hexdigest()


def main():
    query_file = sys.argv[1]
    command3_file = sys.argv[2]
    output_file = sys.argv[3]

    query = ''
    command3 = ''

    with open(query_file) as f:
        query = f.read().strip()

    with open(command3_file) as f:
        command3 = f.read().strip()

    # before hashed part of url, we have 39 characters
    # Add 8 to account for password length
    orig_hash = query[6:38]
    # print(orig_hash)
    orig_message_len = len(query[39:]) + 8

    new_hash = length_extension(orig_hash, orig_message_len, command3)
    with open(output_file, 'w') as f:
        f.write(f'token={new_hash}{query[38:]}{quote_from_bytes(padding(orig_message_len*8))}{command3}')

def test():
    k = b'12345678'
    m = b'user=admin&command1=ListFiles&command2=NoOp'
    command3 = b'&command3=DeleteAllFiles'
    m_prime = b'user=admin&command1=ListFiles&command2=NoOp'+ padding(len(k+m)*8) + command3
    print(m_prime)
    h_key = md5()
    h_key.update(k + m)
    
    h_check = md5()
    h_check.update(k + m_prime)
    
    print(h_check.hexdigest())
    assert length_extension(h_key.hexdigest(), len(k+m), command3) == h_check.hexdigest()

main()
# test()