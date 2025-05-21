import re
import requests
import os
from typing import List, Set

def extract_ips(content: str) -> Set[str]:
    """Extract IP addresses from text content using regex."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return set(re.findall(ip_pattern, content))

def fetch_and_extract_ips(output_file: str = "ips.txt") -> int:
    """Download URLhaus data and extract unique IPs."""
    try:
        # Download the URLhaus data
        response = requests.get("https://urlhaus.abuse.ch/downloads/text/", timeout=30)
        response.raise_for_status()
        
        # Extract and sort unique IPs
        unique_ips = extract_ips(response.text)
        sorted_ips = sorted(unique_ips)
        
        # Write to output file
        with open(output_file, 'w') as f:
            for ip in sorted_ips:
                f.write(f"{ip}\n")
        
        print(f"[+] Extracted {len(sorted_ips)} unique IPs to {output_file}")
        return len(sorted_ips)
        
    except requests.RequestException as e:
        print(f"[-] Error downloading URLhaus data: {e}")
        return 0
    except IOError as e:
        print(f"[-] Error writing to output file: {e}")
        return 0

if __name__ == "__main__":
    fetch_and_extract_ips() 