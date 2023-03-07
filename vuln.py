#!/usr/bin/env python

import vulners
from prettytable.colortable import ColorTable, Themes
from termcolor import colored


class CVEcheck:

    def __init__(self):
        self.api = None
        self.text_check = None
        self.port = None
        self.ip = None
    def __api_validity_check__(self):
        # code to check if api is available
        try:
            with open("vuln_api", "r") as file:
                self.api = file.readline()
            try:
                self.api = vulners.VulnersApi(api_key=self.api)
                return True
            except:
                print(f"API key {self.api} is not working. please check it again")
                return False

        except FileNotFoundError:
            print(f"Go to https://vulners.com/ and request for a free api. paste it into a file called vuln_api")
            return False

    def vulnerability_check(self, ip, port, text):
        self.ip = ip
        self.port = port
        self.text_check = text
        if not self.__api_validity_check__():
            return
        res = self.api.find_exploit(str(self.text_check), limit=5)
        self.__PrintVulnRes__(res)
        return res

    def __PrintVulnRes__(self, results):
        l = len(results)
        table = ColorTable(theme=Themes.OCEAN)
        table.field_names = ["IP Address : Port", 'CVE Code(s)', "Title", "Family", "CVSS", "Link"]
        print(f"\nVulnerability search results for {self.ip}:{self.port} -> {self.text_check}")
        count = 0
        if len(results) == 0: return
        for res in results:
            count += 1
            if count == 1:
                row = [
                    f"{self.ip}: {self.port}", ", ".join(res['cvelist']), res['title'], res['bulletinFamily'],
                    res['cvss']['score'], res['href']
                ]
            else:

                row = [
                    "", ", ".join(res['cvelist']), res['title'], res['bulletinFamily'], res['cvss']['score'], res['href']
            ]
            table.add_row(row)
        print(table)


def scan_vulns(res):
    cve = CVEcheck()
    for ip, port, text in res:
        if len(text) == 0: continue
        cve.vulnerability_check(ip, port, text)

def main():
    text = "Apache/2.2.8 (Ubuntu) DAV/2"
    ip = "192.168.95.44"
    port = "80"
    cve = CVEcheck()
    cve.vulnerability_check(ip, port, text)







if __name__ == '__main__':
    main()