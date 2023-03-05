''''
Scandy is a network scanning tool
version 1.0
'''

import argparse
import socket
import sys
from datetime import datetime



def port_range_conversion(strings):
    # convert port to range of integers
    if strings[0] == 0:
        raise Exception("Port range must start from 1")
    elif strings[1] > strings[0]:
        return list(range(strings[0], strings[1] + 1))
    else:
        raise Exception("Enter a valid port range")


def starting():
    # ====== pretty banner added =====
    with open("../banner.txt") as f:
        file = f.read()
        print(f"\n {file}")

    print(f"{'-' * 60}\n Starting ScAndy at {datetime.now()} \n{'-' * 60}\n")


class ScandyCore:
    # target = str()
    # port = int()
    # port_range = list()

    def __init__(self):

        # pretty banner is printed here
        starting()
        self.openports = list()
        self.closeports = list()

        # the code below parse the input parameters and validate the code first
        parser = argparse.ArgumentParser(
            prog='ScAndy',
            description="Network scanner of a target/ip",
        )
        parser.add_argument('-H', '--Host', metavar='Host target', required=True, help='host to be scanned')

        parser.add_argument('-p', '--port', type=int, metavar='port', help='port of the scan target')

        parser.add_argument('-pr', '--PortRange', type=int, nargs=2, help='Scan Port range.')
        args = parser.parse_args()

        try:
            self.target = socket.gethostbyname(args.Host)
        except socket.gaierror:
            print(f"Hostname {args.Host} could not be resolved")
            sys.exit()

        # Input validators below




        # checks if no port or port range was supplied then it scans first 100 ports
        if args.port is None and (args.PortRange is None):
            args.PortRange = [1, 100]
            self.port_range = port_range_conversion(args.PortRange)

        if args.PortRange is not None:
            self.port_range = port_range_conversion(args.PortRange)

        if args.port is not None:
            # check out of standard port range
            if (args.port <= 0) or (args.port > 65535):
                raise Exception("Port must be between 1 and 65535")
            self.port_range.append(args.port)
            self.port_range = sorted(list(set(self.port_range)))

    # def input_validation(self):
    #     return

    # try:
    #     # no port or port range was provided
    #     if (self.port is None) and (self.port_range is None):
    #         self.port_range = list(range(1, 100))
    #     # if (self.port not in range(1, 65536)) and (type(self.port_range) is None):
    #     #     raise Exception(f"Port {self.port} is invalid. Enter value between 1 and 65536")
    # except:
    #     raise Exception("Something is wrong")


class ScandyOpenPorts(ScandyCore):

    def start(self):
        # this part determines if to scan a single or range of ports based on user input
        try:
            for port in self.port_range:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    socket.setdefaulttimeout(1)
                    if s.connect_ex((self.target, port)):
                        # print(f"Port {port} is close")
                        self.closeports.append(port)
                    else:
                        print(f"Port {port} is open")
                        self.openports.append(port)
        except socket.error:
            print("Could not connect to server")
            sys.exit()
        except KeyboardInterrupt:
            print("Exiting program\n")
            sys.exit()

        return


if __name__ == '__main__':
    f = ScandyOpenPorts()
    f.start()
