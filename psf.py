# This is another project to build a port scanner framework aimed to learn more about Python programming.
# Author: Michael Cruz Sanchez (Search Engineer @lucidworks)
# Copyright: GPLv3+

import argparse
import nmap
import os
from colorama import Fore, Style
from tabulate import tabulate
from CVE.lookup_cve import CVELookup

def scan_ports(target, ports):
    # Create an instance of the Nmap PortScanner
    scanner = nmap.PortScanner()

    # Create an instance of CVELookup
    cve_lookup = CVELookup()

    # Convert the ports argument to a comma-separated string
    ports_str = ','.join(str(port) for port in ports)

    # Perform a TCP scan on the target and specified ports, with OS detection and script scanning
    scanner.scan(target, arguments=f'-p {ports_str} -sV -O --script vulners,smb-vuln-*')

    # Create a list to store scan results
    results = []

    # Get scan results
    if target in scanner.all_hosts():
        host = scanner[target]

        # Store open ports
        for port in host['tcp']:
            port_info = host['tcp'][port]
            if port_info['state'] == 'open':
                results.append([port, port_info['name'], 'Open'])
        
        for result in results:
            if 'vulnerability' in result:
                vulnerability = result['vulnerability']
                cve_id = vulnerability['cve_id']
                cve_description = cve_lookup.lookup_cve(cve_id)
                if cve_description:
                    vulnerability['cve_description'] = cve_description

        # Store detected OS
        detected_os = ''
        if 'osmatch' in host:
            os_match = host['osmatch'][0]
            detected_os = os_match['name']

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
                    results.append(['', '', '', f'Vulnerable: {script_id}'])

        # Add detected OS to the results
        if detected_os:
            results.append(['', '', '', f'Detected OS: {detected_os}'])

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

    # Print the scan results in a tabular format
    print('Port Scan Results:')
    print(tabulate(port_scan_results, headers=['Port', 'Service', 'Status'], tablefmt='presto'))

if __name__ == "__main__":
    main()
