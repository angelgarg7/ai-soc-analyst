def calculate_severity(log_text):
    
    log_text = log_text.lower()

    critical_keywords = [
        "mimikatz",
        "credential dumping",
        "ransomware",
        "lsass",
        "privilege escalation"
    ]

    high_keywords = [
        "powershell",
        "encodedcommand",
        "schtasks",
        "certutil",
        "plink",
        "persistence",
        "lateral movement"
    ]

    medium_keywords = [
        "failed login",
        "bruteforce",
        "suspicious ip",
        "reconnaissance",
        "whoami",
        "ipconfig",
        "net user"
    ]

    low_keywords = [
        "scan",
        "ping",
        "connection attempt"
    ]

    critical_matches = [
        keyword for keyword in critical_keywords
        if keyword in log_text
    ]

    high_matches = [
        keyword for keyword in high_keywords
        if keyword in log_text
    ]

    medium_matches = [
        keyword for keyword in medium_keywords
        if keyword in log_text
    ]

    low_matches = [
        keyword for keyword in low_keywords
        if keyword in log_text
    ]

    if critical_matches:
        return f"CRITICAL ({len(critical_matches)} indicators detected)"

    elif high_matches:
        return f"HIGH ({len(high_matches)} indicators detected)"

    elif medium_matches:
        return f"MEDIUM ({len(medium_matches)} indicators detected)"

    elif low_matches:
        return f"LOW ({len(low_matches)} indicators detected)"

    return "LOW (No major threat indicators detected)"