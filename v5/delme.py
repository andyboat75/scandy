#!/usr/bin/env python

import scapy.all as scapy
def main():
    # ips = scapy.IP(dst="192.168.56.7/24")
    ips = "192.168.56.1/24"
    clients = dict()
    # for ip in ips:
    ip = ips
    s_l = list()
    try:
        ans, unans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") /
                               scapy.ARP(pdst=ip), timeout=3, verbose=False
                               )
        if len(ans) > 0:
            for sent, receive in ans:
                s_l.append(
                    {'ip': receive.psrc, 'mac': receive.hwsrc}
                )
    except Exception as e:
        print(e)
    clients[ips] = s_l
    # print(f"{ip}  : {s_l}")

    return clients

if __name__=='__main__':
    k = main()
    print(k)
