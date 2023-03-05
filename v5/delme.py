#!/bin/python

i = [1,2,3,4]

j = [6,7,8,9,10]

from scapy.all import *

def scan_port(ip, port):
    response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        return True
    else:
        return False

def ip_port_pair(x, y):
    for i in x:
        for j in y:
            yield i, j


def ip_ports_pair(x, y):
    for i in x:
        yield i, y


def main():
    # Define the target IP address and port
    # ip = "172.28.128.3"
    # for port in range(20,200):
    #     if scan_port(ip, port):
    #         print(f"{port}/tcp     open")
    #         continue
    # pass
    ip = list(range(1,10))
    port = list(range(100,1000))
    ip_port_tuple = ip_port_pair(ip,port)
    ip_port_list = ip_ports_pair(ip,port)
    for i in ip_port_list:
        print(i)
    for i in ip_port_tuple:
        print(i)


if __name__ == '__main__':
    main()