# This is another project to build a port scanner framework aimed to learn more about Python programming.
# Author: Michael Cruz Sanchez (Search Engineer @lucidworks)
# Copyright: GPLv3+

import argparse
import json
import nmap
from colorama import Fore, Style
from tabulate import tabulate

def scan(target, ports, os_detection):
    # Create an instance of the Nmap PortScanner
    scanner = nmap.PortScanner()

    # Convert the ports argument to a comma-separated string
    ports_str = ','.join(str(port) for port in ports)

    # Perform a TCP scan on the target and specified ports, with OS detection if enabled
    scanner.scan(target, arguments=f'-p {ports_str} -sV {"-O" if os_detection else ""}')

    # Get scan results
    if target in scanner.all_hosts():
        host = scanner[target]

        # Prepare open ports data for tabulate
        open_ports = []
        for port in host['tcp']:
            port_info = host['tcp'][port]
            if port_info['state'] == 'open':
                open_ports.append([port, port_info['name']])

        # Prepare detected OS data
        os_info = []
        if os_detection and 'osmatch' in host:
            for os_match in host['osmatch']:
                os_info.append([os_match['name'], os_match['accuracy']])

        # Display scan results
        if open_ports:
            print(f"Open ports found on {target}:\n")
            print(tabulate(open_ports, headers=["Port", "Service"], tablefmt="fancy_grid"))
            print()
        else:
            print(f"No open ports found on {target}.")

        # Display detected OS
        if os_info:
            print("Detected OS:\n")
            print(tabulate(os_info, headers=["OS", "Accuracy"], tablefmt="fancy_grid"))

def main():
    # Create the command-line argument parser
    parser = argparse.ArgumentParser(description='Vulnerability Scanner')

    # Add the JSON file argument
    parser.add_argument('file', type=str, help='JSON file containing targets, ports, and OS parameters')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Read JSON file
    with open(args.file) as json_file:
        data = json.load(json_file)

    # Iterate over targets in the JSON data
    for item in data:
        target = item['target']
        ports = item['ports']
        os_detection = item.get('os_detection', False)

        print(f"Scanning target: {target}\n")

        # Perform the scan
        scan(target, ports, os_detection)

        print("\n")

if __name__ == "__main__":
    main()
