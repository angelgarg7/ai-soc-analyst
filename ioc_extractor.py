import re


def extract_iocs(text):

    # IP Addresses
    ips = list(set(re.findall(
        r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b',
        text
    )))

    # URLs
    urls = list(set(re.findall(
        r'https?://[^\\s]+',
        text
    )))

    # Emails
    emails = list(set(re.findall(
        r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+',
        text
    )))

    # MD5
    md5 = list(set(re.findall(
        r'\\b[a-fA-F0-9]{32}\\b',
        text
    )))

    # SHA1
    sha1 = list(set(re.findall(
        r'\\b[a-fA-F0-9]{40}\\b',
        text
    )))

    # SHA256
    sha256 = list(set(re.findall(
        r'\\b[a-fA-F0-9]{64}\\b',
        text
    )))

    # Suspicious EXEs
    suspicious_files = list(set(re.findall(
        r'\\b\\w+\\.exe\\b',
        text
    )))

    return {
        "IPs": ips,
        "URLs": urls,
        "Emails": emails,
        "MD5": md5,
        "SHA1": sha1,
        "SHA256": sha256,
        "Suspicious Files": suspicious_files
    }