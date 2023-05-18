# This is a REST API version of the scanner.
# Author: Michael Cruz Sanchez (Search Engineer @lucidworks)
# Copyright: GPLv3+

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import uvicorn

# Create the FastAPI app
app = FastAPI()

# Model for the Scan Request
class ScanRequest(BaseModel):
    target: str
    ports: List[int]

# Model for the Vulnerability
class Vulnerability(BaseModel):
    script_id: str
    output: str

# Model for the Scan Result
class ScanResult(BaseModel):
    target: str
    open_ports: List[dict]
    detected_os: str
    vulnerabilities: List[Vulnerability]

@app.post("/scan", response_model=ScanResult)
async def scan(scan_request: ScanRequest):
    target = scan_request.target
    ports = scan_request.ports

    # Execute the vulnerability scan
    scan_result = run_vulnerability_scan(target, ports)

    return scan_result

def run_vulnerability_scan(target, ports):
    # Perform the vulnerability scan using your existing scanner logic

    # Example scan results
    open_ports = [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]
    detected_os = "Linux"
    vulnerabilities = [
        {"script_id": "CVE-2021-1234", "output": "Vulnerable to CVE-2021-1234"},
        {"script_id": "CVE-2022-5678", "output": "Vulnerable to CVE-2022-5678"}
    ]

    # Create the ScanResult object
    scan_result = ScanResult(
        target=target,
        open_ports=open_ports,
        detected_os=detected_os,
        vulnerabilities=vulnerabilities
    )

    return scan_result

if __name__ == "__main__":
    # Run the FastAPI app
    uvicorn.run(app, host="0.0.0.0", port=8000)

