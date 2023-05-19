# Port Scanner Framework

The Port Scanner Framework is a Python-based tool that performs port scanning and OS detection on target systems. It allows you to scan multiple targets, specify port ranges, and perform OS detection if needed.
## Features

- Port scanning: Scans specified targets for open ports.
- Port ranges: Supports specifying individual ports, multiple ports, and port ranges.
- OS detection: Provides the option to perform OS detection during the scan.
- Colorful output: Highlights scan results and detected OS information with colors.
- Tabulated results: Displays scan results and detected OS in a formatted table.
- JSON input: Accepts a JSON file as input with targets, ports, and OS parameters.
- Root privilege check: Validates if the scanner is running as root (superuser).


## Prerequisites

- Python 3.x
- nmap module (pip install python-nmap)
- colorama module (pip install colorama)
- tabulate module (pip install tabulate)

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
    "target": "192.168.1.1",
    "ports": ["80", "443", "8080-8090"],
    "os_detection": true
  },
  {
    "target": "192.168.1.2",
    "ports": ["22", "3389"],
    "os_detection": false
  }
]

```

4. Run the scanner
```shell
python psf.py -f file.json
```

5. View the scan results
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


