#!/usr/bin/python

''''
Scandy is a network scanning tool
version 1.2
Features
- Added banner for all open ports
- Stopped printing closed ports and added the banner to the portscan at runtime
Copyright (c) 2023
'''

import argparse
import socket
import sys
import os
import threading
from datetime import datetime
from queue import Queue
from termcolor import colored




class ScandyBasic:

    def __init__(self):
        self.queue = Queue()
        self.port = 0
        self.banner = ''
        self.starting()

        self.openports = list()
        self.closeports = list()
        os.system('color')
        return

    def starting(self):
        # ====== pretty banner added =====
        with open("../banner.txt") as f:
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
            if not self.port == 0 :
                ports.append(self.port)
            # ports.append(self.port)
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
        parser.add_argument('-t', '--Threads', metavar='Number of Threads', type=int, default=50, help='-t 30 or --Threads 40')
        args = parser.parse_args()

        try:
            self.target = socket.gethostbyname(args.Host)
            self.threads = args.Threads
        except socket.gaierror:
            print(f"Hostname {args.Host} could not be resolved")
            sys.exit()

        # Input validators below

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

            # self.queue.put(args.port)

        if args.PortRange is not None:
            self.port_range_conversion(args.PortRange)

            # self.port_range.append(args.port)
            # self.port_range = sorted(list(set(self.port_range)))

    def portscan(self):
        while not self.queue.empty():
            port = self.queue.get()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # socket.setdefaulttimeout(10)
                # socket.settimeout(0.5)
                if s.connect_ex((self.target, port)):
                    # print(colored(f"[-] {port}/tcp close\n", 'red'))
                    self.closeports.append(port)
                else:
                    self.port_banner(port, s)
                    print(colored(f"[+] {port}/tcp open. {str(self.banner)}", 'green'))
                    # print(colored(f"Port {port} is open\n", 'green'))
                    self.openports.append(port)
        return

    def port_banner(self, port, sock):
        with socket.socket() as s:
            s.connect((self.target, port))
            # s.send(b'Banner_query\r\n')
            self.banner = s.recv(1024)
        return

    # def port_banner(self, port, s):
    #     s.send(b'Banner_query\r\n')
    #     self.banner = s.recv(100)
    #     return


if __name__ == '__main__':
    f = ScandyCore()
    f
    thread_list = []

    for t in range(f.threads):
        thread = threading.Thread(target=f.portscan)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()


    print(f"Open ports on host {f.target} are {f.openports}")
