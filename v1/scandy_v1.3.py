#!/usr/bin/python

''''
Scandy is a network scanning tool
version 1.3
Features
- Added banner for all open ports
- Stopped printing closed ports and added the banner to the portscan at runtime
- special for html, ftp
Copyright (c) 2023
'''

try:
    import argparse
    import socket
    import sys
    import os
    import threading
    from datetime import datetime
    from queue import Queue
    from termcolor import colored
    import ftplib
    import vulners
except ImportError:
    print(f"pip install -r {os.getcwd()}/requirements.txt")


class ScandyBasic:

    def __init__(self):
        self.queue = Queue()
        self.port = 0
        self.ports_list = list()
        self.banner = b''
        self.starting()
        self.openports = list()
        self.closeports = list()

        os.system('color')
        self.vulners_api = vulners.VulnersApi(
            api_key="#")

        return

    def starting(self):
        # ====== pretty banner added =====
        with open("banner.txt") as f:
            file = f.read()
            print(f"\n {file}")

        print(f"{'-' * 60}\n Starting ScAndy at {datetime.now()} \n{'-' * 60}\n")
        return

    def port_range_conversion(self, strings):
        ports = list()
        # convert port to range of integers
        if strings[0] <= 0 or strings[1] > 65535:
            print("Port range must be between 1 to 65535")
            sys.exit()

        elif strings[1] > strings[0]:
            ports = list(range(strings[0], strings[1] + 1))
            if not self.port == 0:
                ports.append(self.port)
            ports.append(self.port)
            ports = list(set(ports))
            ports.sort()
            for p in ports:
                self.queue.put(p)
            return

        else:
            print("Enter a valid port range")
            sys.exit()


class ScandyCore(ScandyBasic):

    def __init__(self):
        super().__init__()

        # the code below parse the input parameters and validate the code first
        parser = argparse.ArgumentParser(
            prog='ScAndy',
            description="Network scanner of a target/ip",
        )
        parser.add_argument('-H', '--Host', metavar='Host target', required=True, help='host to be scanned.'
                                                                                       'Example -H 127.0.0.1 or --Host localhost')

        parser.add_argument('-p', '--port', type=int, metavar='port', help='port of the scan target. Example -p 80 or'
                                                                           ' --port 80')

        parser.add_argument('-pr', '--PortRange', type=int, nargs=2, help='Scan Port range. Example -pr 1 100')
        parser.add_argument('-t', '--Threads', metavar='Number of Threads', type=int,
                            default=50, help='-t 30 or --Threads 40')

        parser.add_argument('-v', '--version', action='store', nargs='?', dest='verbose', default='no',
                            help='Verbose')
        args = parser.parse_args()

        try:
            self.target = socket.gethostbyname(args.Host)
            self.threads = args.Threads
        except socket.gaierror:
            print(f"Hostname {args.Host} could not be resolved")
            sys.exit()

        try:
            self.hostname = socket.gethostbyaddr(self.target)
            print(f"Hostname - {self.hostname[0]}")
        except socket.herror:
            pass

        # Input validators below
        self.verbose = args.verbose

        # checks if no port or port range was supplied then it scans first 100 ports
        if args.port is None and (args.PortRange is None):
            args.PortRange = [1, 100]
            # self.port_range_conversion(args.PortRange)

        if args.port is not None:
            # check out of standard port range
            if (args.port <= 0) or (args.port > 65535):
                print("Port must be between 1 and 65535")
                sys.exit()
            self.port = args.port
            if args.PortRange is None:
                self.queue.put(args.port)

            # self.queue.put(args.port)

        if args.PortRange is not None:
            self.port_range_conversion(args.PortRange)

            # self.port_range.append(args.port)
            # self.port_range = sorted(list(set(self.port_range)))

    def portscan(self):
        while not self.queue.empty():
            port = self.queue.get()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    # socket.setdefaulttimeout(10)
                    s.settimeout(10)
                    if s.connect_ex((self.target, port)):
                        if self.verbose != 'no':
                            print(colored(f"[-] {port}/tcp close\n", 'red'))
                        self.closeports.append(port)
                    else:
                        self.port_banner(port, s)
                        print(colored(f"[+] {port}/tcp open. {str(self.banner)}", 'green'))
                        # print(colored(f"Port {port} is open\n", 'green'))
                        self.openports.append(port)
                        self.vulnerability_check()

                        self.banner = b""
            except TimeoutError:
                pass

        return

    def port_banner(self, port, sock):
        try:
            with socket.socket() as s:
                s.settimeout(1)
                s.connect((self.target, port))
                s.send(b'Banner_query\r\n')
                try:
                    self.banner = s.recv(100)
                except ConnectionResetError:
                    self.banner = b'Connection Reset error'
                if 'html' in str(self.banner):
                    self.html_port(port)
                elif 'ftp' in str(self.banner).lower():
                    self.ftp_port(port)
                # else:
                #     self.banner = self.banner.decode()
                # self.banner.decode().strip('\n').strip('\r')
        except:
            pass
        return

    def html_port(self, port):
        try:
            s = socket.socket()
            s.connect((self.target, port))
            s.send(b"GET / HTTP/1.0\r\n\r\n")
            # print(s.recv(1024))
            k = s.recv(128)
            k = k.decode().split('\r\n')
            self.banner = f"{k[0]}   {k[2]}    {k[3]}"
        except:
            pass
        return

    def ftp_port(self, port):
        # target_host = "192.168.95.44"
        # target_port = 21

        # Create an FTP object
        ftp = ftplib.FTP()

        # Connect to the target host and port
        ftp.connect(self.target, port)

        # Print the banner
        self.banner = ftp.getwelcome()
        try:
            login = ftp.login()
            if 'successful' in login:
                self.banner += colored('    Vulnerable to anonymous login', 'red')
            ftp.quit()
        except:
            pass

    def vulnerability_check(self):
        try:
            if b'Connection Reset error' in self.banner or b'' == self.banner or '/x' in str(self.banner):
                pass
            else:
                res = self.vulners_api.find_exploit(str(self.banner), limit=5)
                print(res)
        except Exception as e:
            print(e)

    # def port_banner(self, port, s):
    #     s.send(b'Banner_query\r\n')
    #     self.banner = s.recv(100)
    #     return


if __name__ == '__main__':
    f = ScandyCore()
    thread_list = []

    for t in range(f.threads):
        thread = threading.Thread(target=f.portscan)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    print(f"Open ports on host {f.target} are {f.openports}")
