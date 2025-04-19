import requests
import re

def get_ip_info(ip):
    response = requests.get(f'https://ipwhois.app/json/{ip}')
    if response.status_code == 200:
        return response.json()
    return None

def extract_ips(received_lines):
    ips = []
    for line in received_lines:
        match = re.search(r'\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]', line)
        if match:
            ips.append(match.group(1))
    return ips
