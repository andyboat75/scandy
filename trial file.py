#

# from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
#
# packet = IP(b'192.168.95.44')
# mtu_result = fingerprint_mtu(packet)
# tcp_result = fingerprint_tcp(packet)
# http_result = fingerprint_http(packet)
#
# print(mtu_result.match.label.name)  # Ethernet or modem
# print(tcp_result.match.record.label.dump())  # s:win:Windows:7 or 8
# print(http_result.match.label.dump())  # s:!:nginx:1.x


# from scapy.all import *
#
# target_ip = "192.168.95.44"
# target_port = 80
#
# # Create a SYN packet
# syn = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
#
# # Send the SYN packet and receive the response
# response = sr1(syn, timeout=1, verbose=False)
#
# # Check if the response is a SYN-ACK packet
# if response and response.haslayer(TCP) and response[TCP].flags == "SA":
#     # Print the banner
#     print(f"Banner for port {target_port}: {str(response[TCP].payload)}")
# else:
#     # Port is closed or filtered
#     print(f"Port {target_port} is closed or filtered")

# !/usr/bin/python

# import socket
#
# def retBanner(ip, port):
#     try:
#         with socket.socket() as s:
#             socket.setdefaulttimeout(1)
#             s.connect((ip, port))
#             # banner = s.recv(1024)
#             s.send(b'Banner_query\r\n')
#             banner = s.recv(100)
#             return banner
#     except:
#         return
#
# def main():
#     # port = 22
#     ip = '192.168.95.44'
#     for port in range(1,100):
#         banner = retBanner(ip, port)
#         if banner:
#             print(f"[+] {ip}/{port}: {banner}")
#     return


#

import scapy.all as scapy
from scapy.all import *

warnings.simplefilter('ignore')


def scan(ip):
    arp_req_frame = scapy.ARP(pdst=ip)

    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        result.append(client_dict)
    print(result)
    return result


# import p0f
def main():
    # packet = IP()
    # print(packet.name)
    # Ether(dst="ff:ff:ff:ff:ff:ff")

    # ip = "brytafoods.com"
    # ip = "192.168.95.10"
    # # ip = socket.gethostbyname(ip)
    # ans, unans = sr(IP(src=get_if_addr(conf.iface), dst=ip) / ICMP(), timeout=3, verbose=False)

    # for i in ans:
    #     print(i.answer.src)
    #     print(get_if_hwaddr(i.answer.src))
    #     print('hello')
    # ip = "google.com"
    # ip = socket.gethostbyname(ip)
    # ans = scan(ip)

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.95.44/24"), timeout=2, verbose=False)
    # ICMP(IP(dst="192.168.95.44", src="192.168.95.136"))
    for i in ans:
        # load_module("p0f")
        # print(p0f(i))
        print(i.answer.payload.psrc, i.answer.payload.hwsrc)
    print('hi')

    # mtu_result = fingerprint_mtu(packet)
    # tcp_result = fingerprint_tcp(packet)
    # http_result = fingerprint_http(packet)
    #
    # print(mtu_result.match.label.name)  # Ethernet or modem
    # print(tcp_result.match.record.label.dump())  # s:win:Windows:7 or 8
    # print(http_result.match.label.dump())  # s:!:nginx:1.x


# from manuf import manuf
# from scapy.layers.l2 import getmacbyip
# def main():
#     p = manuf.MacParser(update=False)
#     a = getmacbyip("192.168.95.44").upper()
#     print(a)
#     # a = '00:50:C2:D2:80:00'
#     c = p.get_all(a)
#     print(type(c))
#     print(c.manuf)


# from scapy.all import *
#
# # Define the target IP address or network range
# def main():
#     target_ip = "192.168.95.136"
#     # Send ICMP echo requests to each IP address in the target range
#     ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / ICMP(), timeout=2)
#
#     # Print the live hosts
#     print("Live hosts:")
#     for snd, rcv in ans:
#         print(rcv.sprintf("%IP.src%"))
#
#     # Print the unresponsive hosts
#     print("\nUnresponsive hosts:")
#     for snd, rcv in unans:
#         print(rcv.sprintf("%IP.dst%"))


# import requests
# from manuf import manuf
# from scapy.all import *
#
# def main():
#     # Define the target MAC address
#     p = manuf.MacParser(update=False)
#
#     target_mac = "f3:ae:5e:76:31:9b"
#     print(target_mac)
#
#     # Retrieve the manufacturer information from the IEEE database
#     url = "http://standards-oui.ieee.org/oui.txt"
#     response = requests.get(url)
#     if response.status_code == 200:
#         oui_database = response.text
#         manufacturer = ""
#         for line in oui_database.split("\n"):
#             if line.startswith(target_mac.replace(":", "")):
#                 manufacturer = line.split("(hex)")[1].strip()
#                 break
#         if manufacturer:
#             print(f"Manufacturer: {manufacturer}")
#         else:
#             print("Manufacturer not found in database.")
#     else:
#         print("Failed to retrieve OUI database.")

# import p0f
# import socket
# import requests
# def main():
#     s = socket.socket()
#
#     s.connect(('192.168.95.44', 80))
#     s.send(b"GET / HTTP/1.0\r\n\r\n")
#     # print(s.recv(1024))
#     k = s.recv(128)
#     k = k.decode().split('\r\n')
#     print(f"{k[0]}   {k[2]}    {k[3]}")

# import telnetlib
#
# def main():
#     target_ip = "192.168.95.44"
#     # target_port = 80
#     for target_port in range(1, 1001):
#         try:
#             # Connect to the Telnet service
#             tn = telnetlib.Telnet(target_ip, target_port, timeout=1)
#
#             # Read the banner message
#             banner = tn.read_until(b"zaiesedtgwseqeserweqawqrwrdrf", timeout=1)
#             print(target_port, banner)
#             # print(tn.read_all())
#             # print(tn.read_all())
#
#             # Print the banner message
#             # print(f"Banner for port {target_port}: {banner.decode()}")
#
#             # Close the connection
#             tn.close()
#
#         except ConnectionRefusedError:
#             # Port is closed or filtered
#             print(f"Port {target_port} is closed or filtered")
#         except:
#             pass


# import ftplib
#
#
# def main():
#     target_host = "192.168.95.44"
#     target_port = 21
#
#     # Create an FTP object
#     ftp = ftplib.FTP()
#
#     # Connect to the target host and port
#     ftp.connect(target_host, target_port)
#
#     # Print the banner
#     # print(f"Banner for port {target_port}: {ftp.getwelcome()}")
#     try:
#         login = ftp.login()
#         if 'successful' in login:
#             print('Vulnerable to anonymous login')
#     except:
#         pass

# Close the FTP connection
# ftp.quit()

# import socket
# import sys
# target = "192.168.95.44"
# port = 139
# def main():
#     try:
#         with socket.socket() as s:
#             # s.settimeout(10)
#             s.connect((target, port))
#             s.send(b'Banner_query\r\n')
#
#             try:
#                 banner = s.recv(100)
#             except ConnectionResetError:
#                 banner = b'Connection Reset error'
#             except Exception as e:
#                 print(e)
#         print(banner)
#     except:
#         pass


# import socket
#
#
# def main(ip="192.168.95.44", port=21, method="HEAD", timeout=60, http_type="HTTP/1.1"):
#     assert method in ['GET', 'HEAD']
#     # @see: http://stackoverflow.com/q/246859/538284
#     assert http_type in ['HTTP/0.9', "HTTP/1.0", 'HTTP/1.1']
#     cr_lf = '\r\n'
#     lf_lf = '\n\n'
#     crlf_crlf = cr_lf + cr_lf
#     res_sep = ''
#     # how much read from buffer socket in every read
#     rec_chunk = 4096
#     s = socket.socket()
#     s.settimeout(timeout)
#     s.connect((ip, port))
#     # the req_data is like 'HEAD HTTP/1.1 \r\n'
#     req_data = "{} / {}{}".format(method, http_type, cr_lf)
#     # if is a HTTP 1.1 protocol request,
#     if http_type == "HTTP/1.1":
#         # then we need to send Host header (we send ip instead of host here!)
#         # adding host header to req_data like 'Host: google.com:80\r\n'
#         req_data += 'Host: {}:{}{}'.format(ip, port, cr_lf)
#         # set connection header to close for HTTP 1.1
#         # adding connection header to req_data like 'Connection: close\r\n'
#         req_data += "Connection: close{}".format(cr_lf)
#     # headers join together with `\r\n` and ends with `\r\n\r\n`
#     # adding '\r\n' to end of req_data
#     req_data += cr_lf
#     # the s.send() method may send only partial content.
#     # so we used s.sendall()
#     s.sendall(req_data.encode())
#     res_data = b''
#     # default maximum header response is different in web servers: 4k, 8k, 16k
#     # @see: http://stackoverflow.com/a/8623061/538284
#     # the s.recv(n) method may receive less than n bytes,
#     # so we used it in while.
#     while 1:
#         try:
#             chunk = s.recv(rec_chunk)
#             res_data += chunk
#         except socket.error:
#             break
#         if not chunk:
#             break
#     if res_data:
#         # decode `res_data` after reading all content of data buffer
#         res_data = res_data.decode()
#     else:
#         return '', ''
#     # detect header and body separated that is '\r\n\r\n' or '\n\n'
#     if crlf_crlf in res_data:
#         res_sep = crlf_crlf
#     elif lf_lf in res_data:
#         res_sep = lf_lf
#     # for under HTTP/1.0 request type for servers doesn't support it
#     #  and servers send just send body without header !
#     if res_sep not in [crlf_crlf, lf_lf] or res_data.startswith('<'):
#         return '', res_data
#     # split header and data section from
#     # `HEADER\r\n\r\nBODY` response or `HEADER\n\nBODY` response
#     content = res_data.split(res_sep)
#     banner, body = "".join(content[:1]), "".join(content[1:])
#     print(banner)
#     return banner, body

# import requests as requ
#
# def main():
#     ploads = {'points': 3, 'total': 10}
#
#     req = requ.get('http://172.28.128.3:80', params=ploads)
#
#     # print(req.text)
#
#     print(req.headers)
def host_stat(ip):
    if subprocess.call(f"ping -c 1 {ip}", stdout=False, stderr=False) == 0 or \
            subprocess.call(f"ping -n 1 {ip}", stdout=False, stderr=False) == 0:
        return True
    return False


if __name__ == '__main__':
    # print(host_stat('192.168.95.245'))
    main()

    # def port_banner(self, s, port):
    #     banner = ""
    #     teln_banner_grabber = range(1,80)
    #     if port in teln_banner_grabber:
    #         banner = self.port_banner2(port)
    #     else:
    #         try:
    #             with socket.socket() as s:
    #                 s.settimeout(1)
    #                 s.connect((self.target, port))
    #                 s.send(b'Banner_query\r\n')
    #                 try:
    #                     banner = s.recv(100)
    #                 except ConnectionResetError:
    #                     pass
    #
    #
    #                 # else:
    #                 #     self.banner = self.banner.decode()
    #                 # self.banner.decode().strip('\n').strip('\r')
    #         except:
    #             pass
    #     if 'html' in str(banner).lower() or 'http' in str(banner).lower():
    #         banner = self.html_port(port)
    #     if 'ftp' in str(banner).lower():
    #         banner = self.ftp_port(port)
    #
    #     return banner.decode('utf-8')
