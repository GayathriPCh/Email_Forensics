def generate_report(email_data, indicators, score):
    return {
        'Sender Info': email_data.get('From', ''),
        'Indicators Found': indicators,
        'Phishing Score': score,
        'Raw Headers': email_data
    }
