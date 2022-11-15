from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])
    
    # SYN scan
    print("# ip_addr: ", ip_addr)
    print("# my_ip: ", my_ip)

    ans, unans = sr(IP(dst=ip_addr)/TCP(dport=(1,1024),flags="S"), timeout=30, verbose=0)
    for snd,rcv in ans:
        #print(snd., rcv.flags)
        port = rcv.sprintf("%r,TCP.sport%")
        flags = rcv.sprintf("%TCP.flags%")
        if flags == "SA":
            print(ip_addr, ", ", port)
            ans1, unans1 = sr(IP(dst=ip_addr)/TCP(dport=int(port),flags="R"), timeout=15, verbose=0)
