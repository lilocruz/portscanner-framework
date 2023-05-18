# This is another project to build a port scanner framework aimed to learn more about Python programming.
# Author: Michael Cruz Sanchez (Search Engineer @lucidworks)
# Copyright: GPLv3+

import argparse
import json
import nmap
import os
from colorama import Fore, Style

def scan_ports(target, ports):
    # Create an instance of the Nmap PortScanner
    scanner = nmap.PortScanner()

    # Convert the ports argument to a comma-separated string
    ports_str = ','.join(str(port) for port in ports)

    # Perform a TCP scan on the target and specified ports, with OS detection and script scanning
    scanner.scan(target, arguments=f'-p {ports_str} -sV -O --script vulners,smb-vuln-*')

    # Create a dictionary to store scan results
    results = {
        'target': target,
        'open_ports': [],
        'detected_os': '',
        'vulnerabilities': []
    }

    # Get scan results
    if target in scanner.all_hosts():
        host = scanner[target]

        # Store open ports
        for port in host['tcp']:
            port_info = host['tcp'][port]
            if port_info['state'] == 'open':
                results['open_ports'].append({'port': port, 'service': port_info['name']})

        # Store detected OS
        if 'osmatch' in host:
            os_match = host['osmatch'][0]
            results['detected_os'] = os_match['name']

        # Store detected vulnerabilities
        if 'script' in host:
            scripts = host['script']
            for script_id in scripts:
                script_output = scripts[script_id]
                if 'VULNERABLE' in script_output:
                    vulnerability = {
                        'script_id': script_id,
                        'output': script_output
                    }
                    results['vulnerabilities'].append(vulnerability)

    return results

def main():
    # Check if script is running with root privileges
    if os.geteuid() != 0:
        print("The port scanner framework requires root privileges to perform certain scans. Please run it as root or with sudo.")
        return

    # Create the command-line argument parser
    parser = argparse.ArgumentParser(description='Port Scanner Framework by Michael Cruz Sanchez')

    # Add the target argument
    parser.add_argument('target', type=str, help='Target IP address or hostname to scan')

    # Add the ports argument
    parser.add_argument('ports', nargs='+', help='Ports to scan (range, multiple, or single)')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Parse the ports argument as a range, multiple, or single ports
    ports = []
    for port in args.ports:
        if '-' in port:
            start, end = port.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(port))

    # Perform the port scan
    port_scan_results = scan_ports(args.target, ports)

    # Create a dictionary to store overall scan results
    scan_results = {
        'target': args.target,
        'port_scan': port_scan_results
    }

    # Convert scan results to JSON format with enhanced structure
    json_output = json.dumps(scan_results, indent=4)
    print(json_output)

if __name__ == "__main__":
    main()