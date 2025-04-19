import re

def parse_email(headers):
    email_data = {}
    # Split headers by new lines
    lines = headers.strip().split('\n')
    
    for line in lines:
        if line.startswith('From:'):
            email_data['From'] = line[6:].strip()
        elif line.startswith('To:'):
            email_data['To'] = line[4:].strip()
        elif line.startswith('Subject:'):
            email_data['Subject'] = line[8:].strip()
        elif line.startswith('Received:'):
            email_data.setdefault('Received', []).append(line[9:].strip())
        elif line.startswith('Return-Path:'):
            email_data['Return-Path'] = line[13:].strip()
    
    return email_data
