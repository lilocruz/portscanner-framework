# Port Scanner Framework

The Port Scanner Framework is a Python-based tool for conducting vulnerability assessments on target systems. It combines port scanning, OS detection, and Nmap scripts to identify potential vulnerabilities.

## Features

- Port scanning: Scan specified ports on a target system to identify open ports and associated services.
- OS detection: Detect the operating system running on the target system.
- Nmap scripts: Utilize Nmap scripts (vulners, smb-vuln-*) to identify known vulnerabilities.
- JSON output: Generate scan results in JSON format for further analysis.

## Prerequisites

- Python 3.x
- Nmap (https://nmap.org/)

## Usage

1. Clone the repository:

```shell
git clone https://github.com/lilocruz/portscanner-framework
```

2. Install the dependencies
```shell
pip install -r requirements.txt
```

3. Run the scanner
```shell
python psf.py <target> <ports>
```

Replace <target> with the IP address or hostname of the target system, and <ports> with the ports to scan (range, multiples, or single). For example:

```shell
python psf.py 192.168.0.1 80 443
python psf.py example.com 1-100
```

4. View the scan results
The scan results will be displayed in the console, providing information about open ports, detected OS, and any vulnerabilities found.

## Sample Output

```json
{
    "target": "192.168.0.1",
    "port_scan": {
        "target": "192.168.0.1",
        "open_ports": [
            {
                "port": 80,
                "service": "http"
            },
            {
                "port": 443,
                "service": "https"
            }
        ],
        "detected_os": "Linux",
        "vulnerabilities": []
    },
    "web_scan": {
        "target": "192.168.0.1",
        "web_scan_results": "Nikto output...",
        "vulnerabilities": [
            {
                "name": "Cross-Site Scripting (XSS)",
                "description": "..."
            },
            {
                "name": "Directory Listing Enabled",
                "description": "..."
            }
        ]
    }
}
```

## License

This project is licensed under the GPLv3+ License.


