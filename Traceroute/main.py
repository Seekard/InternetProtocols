import re
import subprocess
from ipaddress import IPv4Address
import requests
from prettytable import PrettyTable
import sys
from typing import List, Dict

MAIN_IP_INFO = ['ip', 'as', 'country', 'provider']

def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] == 'help'):
        print_help()
        exit(0)
    if len(sys.argv) == 2:
        target = sys.argv[1]
    else:
        target = input("Enter domain or ip address: ")
    traceroute = get_traceroute(target)
    info = [get_main_info_about_ip(ip) for ip in traceroute]
    print_info_about_traceroute(info)


def get_traceroute(ip: str) -> List[IPv4Address]:
    process = subprocess.Popen('tracert ' + ip, stdout=subprocess.PIPE, shell=True, universal_newlines=True)
    process.stdout.readline()  # Skip line
    process.stdout.readline()  # Skip line
    process.stdout.readline()  # Skip line
    for line in process.stdout:
        ip = parse_line(line)
        if ip is not None:
            yield ip
    process.kill()


ipv4_extract_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
def parse_line(line: str) -> IPv4Address:
    ip_address = ipv4_extract_pattern.findall(line)
    if len(ip_address) == 0:
        return None
    return IPv4Address(ip_address[0])


def get_info_about_ip(ip: IPv4Address) -> Dict:
    try:
        asns = parse_response(lambda: requests.get(url=f"https://stat.ripe.net/data/network-info/data.json?resource={str(ip)}").json()['data']['asns'][0])
        country = parse_response(lambda: requests.get(url=f"https://stat.ripe.net/data/geoloc/data.json?resource={str(ip)}").json()['data']['located_resources'][0]['locations'][0]['country'])
        provider = parse_response(lambda: requests.get(url=f"https://stat.ripe.net/data/as-overview/data.json?resource={asns}").json()['data']['holder'])
        return {'ip': str(ip),
                'as': asns,
                'country': country,
                'provider': provider}
    except requests.exceptions.ConnectionError:
        print("Smth went wrong.")
        print("Try to check your internet connection.")


def parse_response(func_to_get_data):
    try:
        response = func_to_get_data()
        return response
    except:
        return "---"


def get_main_info_about_ip(ip: IPv4Address) -> Dict:
    if not ip.is_global:
        main_info = {key: "---" for key in MAIN_IP_INFO}
        main_info["ip"] = ip
        return main_info
    response = get_info_about_ip(ip)
    main_info = {key: response[key] for key in MAIN_IP_INFO}
    return main_info


def print_info_about_traceroute(info: List):
    table = PrettyTable()
    table.field_names = ["#", "Ip Address", "As", "Country", "Provider"]
    for i in range(len(info)):
        ip_info = info[i]
        table.add_row([i, *ip_info.values()])
    print(table)


def print_help():
    print("Traceroute: ")
    print("\tUsage:")
    print("\t\t python main.py [ipAddress/domain]")

if __name__ == "__main__":
    main()
