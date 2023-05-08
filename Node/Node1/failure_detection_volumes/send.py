#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import IP, UDP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    tos = sys.argv[2]
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='08:00:00:00:03:33')
    pkt = pkt /IP(dst=addr, tos=int(tos)) / UDP(dport=5001, sport=random.randint(49152,65535)) / sys.argv[3]
    pkt.show2()
    for i in range(int(sys.argv[4])):
        sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
