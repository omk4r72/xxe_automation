# XXE Attack Automation Tool

![XXE Tool]()

This Python script automates the execution of XML External Entity (XXE) attacks, including Local File Inclusion (LFI), Remote File Inclusion (RFI), Out-Of-Band (OOB) data exfiltration, and internal network scanning.

## Features
- Supports multiple XXE payloads (LFI, RFI, OOB).
- Injects custom XXE payloads.
- Scans internal network resources.
- Visual display of blinking ASCII art.

## Installation   
https://github.com/omk4r72/xxe_automation.git
cd xxe
python xxe.py -u <target_url> -x <xml_file> -a <attack_type> [-p <payload_file>] [-ih <internal_host>]

1. Local File Inclusion (LFI)
python xxe.py -u http://example.com/vulnerable-endpoint -a lfi
2. Remote File Inclusion (RFI) with a custom payload
python xxe.py -u http://example.com/vulnerable-endpoint -a rfi -p custom_payload.xml


Disclaimer
This tool is designed for educational purposes only and should only be used in environments where you have explicit permission to test. Unauthorized use of this tool on networks or systems where you do not have permission may be illegal.
