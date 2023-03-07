import scapy.all as scapy

def main():

    ip = "192.168.95.44"
    try:
        ans, unans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") /
                               scapy.ARP(pdst=ip), timeout=3, verbose=False
                               )
    except Exception as e:
        print(e)
        # continue
    if len(ans) > 0:
        act_ip = ans[-1]
        mac = act_ip.answer.payload.hwsrc.upper()
        # print(f"{ip}\t{mac}\t{self.mac_manufactuer(mac)}")
        # self.active_ips.append((act_ip.answer.payload.psrc, mac))


if __name__ == '__main__':
    main()