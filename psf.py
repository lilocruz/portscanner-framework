# This is another project to build a port scanner framework aimed to learn more about Python programming.
# Author: Michael Cruz Sanchez (Search Engineer @lucidworks)
# Copyright: GPLv3+

import argparse
import nmap

def scan(target, ports):
    # Create an instance of the Nmap PortScanner
    scanner = nmap.PortScanner()

    # Convert the ports argument to a comma-separated string
    ports_str = ','.join(str(port) for port in ports)

    # Perform a TCP scan on the target and specified ports
    scanner.scan(target, arguments=f'-p {ports_str} -sV')

    # Get scan results
    if target in scanner.all_hosts():
        host = scanner[target]
        for port in host['tcp']:
            port_info = host['tcp'][port]
            if port_info['state'] == 'open':
                print(f"Open port found: {port}/{port_info['name']}")

def main():
    # Create the command-line argument parser
    parser = argparse.ArgumentParser(description='Vulnerability Scanner')

    # Add the target argument
    parser.add_argument('target', type=str, help='Target IP address or hostname to scan')

    # Add the ports argument as a list of integers
    parser.add_argument('ports', type=int, nargs='+', help='Ports to scan (space-separated)')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Perform the scan
    scan(args.target, args.ports)

if __name__ == "__main__":
    main()
