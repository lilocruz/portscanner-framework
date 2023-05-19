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

3. Create a JSON file with the targets to scan
```json
[
    {
      "target": "<IP>",
      "ports": [22, 80, 443]
    },
    {
      "target": "<IP>",
      "ports": [22, 80],
      "os_detection": true
    }
  ]
```

Replace <IP> with the targets IP addresses.

3. Run the scanner
```shell
python psf.py file.json
```

4. View the scan results
The scan results will be displayed in the console, providing information about open ports, detected OS, and any vulnerabilities found.

## Sample Output

```tabulate
Scanning target: <IP>

Open ports found on <IP>:

╒════════╤═══════════╕
│   Port │ Service   │
╞════════╪═══════════╡
│     22 │ ssh       │
├────────┼───────────┤
│     80 │ http      │
╘════════╧═══════════╛



Scanning target: <IP>

Open ports found on <IP>:

╒════════╤═══════════╕
│   Port │ Service   │
╞════════╪═══════════╡
│     22 │ ssh       │
╘════════╧═══════════╛

Detected OS:

╒══════════════════╤════════════╕
│ OS               │   Accuracy │
╞══════════════════╪════════════╡
│ Linux 4.15 - 5.6 │        100 │
╘══════════════════╧════════════╛
```

## License

This project is licensed under the GPLv3+ License.


