#!/bin/python

from ScandyBasic import *
from datetime import datetime

class Scandy(ScandyBasic):
    def __init__(self):
        super().__init__()
        self.target = self.args.target

    def portscan(self, ip_ports):
        # print("portscan working")
        # # ip, port = ip_port
        # print(f'{ip_port}\n')
        # ans, unans = scapy.sr(scapy.IP(dst=ip_port[0]) /
        #                       scapy.TCP(sport=scapy.RandShort(), dport=ip_port[-1], flags="S"))
        # print(ans.summary())
        # print('working')
        # ip = ip_ports[0]
        # ports = ip_ports[-1]
        res = dict()
        message = ''
        status = ''
        banner = ''
        for ip, port in ip_ports:
            if ip not in res.keys():
                res[ip] = list()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                if s.connect_ex((ip, port)):
                    if self.args.Verbose:
                        # service = portservice(port)
                        if self.realtime:
                            # message = f"{port}/tcp\t     {colored('close', 'red')}\n"
                            message = f"[-] {port}/tcp{'':<10} {colored('close', 'red')}{'':<10} {'':<10} {'':<10}"
                            print(message)
                        status = colored('close', 'red')
                        res[ip].append({
                            'status': status,
                            'port': port
                        })
                        continue
                else:
                    service = port_service(port)
                    banner = self.port_banner(s, ip, port)
                    status = colored('open', 'green')
                    # message = f"{port}\t     {colored('open', 'green')}\t     {service} {banner}"
                    message = f"[+] {port} {'':<10}{colored(status, 'green')}{'':<10}{service}{'':<10}{banner} {'':<10}"
                    if self.realtime:
                        print(message)
                    # print(message)
                    res[ip].append({
                        'status': status,
                        'service': service,
                        'port': port,
                        'banner': banner
                    })
            message, status, banner = '', '', ''
        return res


def main():
    f = Scandy()
    p = f.port_port_range_validator()
    f.scan_ports = list(set([i for i in p]))
    f.scan_ports.sort()

    print(f"Starting ScAndy at local:{datetime.now().strftime('%d/%m/%Y, %H:%M:%S')}"
          f"\n\n"
          f"Scanning for connected devices on the network"
          f" {f.args.target}")

    # scan for devices on the network
    all_ips = f.target_ip_processor()
    print(colored(f"{'-' * 120}\nIP Address{'':<10}\tHostname{'':<10}\tMAC Address{'':<10}\tManufacturer\n{'-' * 120}", 'blue'))
    k = f.speed(f.ip_validator, all_ips)
    active_ips = list(set([x for x, y in k]))
    print(f"{colored(len(active_ips),'green')} were discovered")

    active_ips.sort()
    if len(active_ips) == 0:
        print(colored(f"{all_ips} cannot be reached", 'red'))
        sys.exit()
    # print(f"\nScanning for open ports ...")
    # print("{:<15} {:<15} {:<15} {:<15}".format('Ports', 'States', 'Service', 'Banner'))
    res = f.speed(f.portscan, active_ips, f.scan_ports)
    f.table_print(res)


if __name__ == '__main__':
    main()
