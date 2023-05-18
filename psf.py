# This is another project to build a port scanner framework aimed to learn more about Python programming.
# Author: Michael Cruz Sanchez (Search Engineer @lucidworks)
# Copyright: GPLv3+

import argparse
import nmap

def scan(target):
    # Create the instance of the Nmap PortScanner
    scanner = nmap.PortScanner()

    # Perform a TCP scan on the target
    scanner.scan(target, arguments='-p1-65535 -sV')

    # Get the scan results
    if target in scanner.all_hosts():
        host = scanner[target]
        for port in host['tcp']:
            port_info = host['tcp'][port]
            if port_info['state'] == 'open':
                print(f"Open port found: {port}/{port_info['name']}")

def main():
    # Create the command-line argument parser
    parser = argparse.ArgumentParser(description='Port Scanner Framework')

    # Add the target argument
    parser.add_argument('target', type=str, help='Target IP address or hostname to scan')

    # Parse the command-line argument
    args = parser.parse_args()

    # Perform the scan
    scan(args.target)

if __name__ == '__main__':
    main()