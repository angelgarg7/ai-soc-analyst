def map_mitre(log_text):
    
    techniques = []

    text = log_text.lower()

    # PowerShell Execution
    if "powershell" in text:
        techniques.append(
            {
                "Technique": "T1059",
                "Name": "Command and Scripting Interpreter"
            }
        )

    # Scheduled Tasks Persistence
    if "scheduled task" in text or "schtasks" in text:
        techniques.append(
            {
                "Technique": "T1053",
                "Name": "Scheduled Task Persistence"
            }
        )

    # Credential Dumping
    if "mimikatz" in text:
        techniques.append(
            {
                "Technique": "T1003",
                "Name": "Credential Dumping"
            }
        )

    # Remote Services / RDP
    if "mstsc" in text or "rdp" in text:
        techniques.append(
            {
                "Technique": "T1021",
                "Name": "Remote Services"
            }
        )

    # LOLBins Abuse
    if "certutil" in text:
        techniques.append(
            {
                "Technique": "T1218",
                "Name": "Signed Binary Proxy Execution"
            }
        )

    # Encoded PowerShell
    if "encodedcommand" in text:
        techniques.append(
            {
                "Technique": "T1027",
                "Name": "Obfuscated Files or Information"
            }
        )

    # Plink / Tunneling
    if "plink" in text:
        techniques.append(
            {
                "Technique": "T1572",
                "Name": "Protocol Tunneling"
            }
        )

    # Discovery Commands
    if "whoami" in text or "ipconfig" in text or "net user" in text:
        techniques.append(
            {
                "Technique": "T1082",
                "Name": "System Information Discovery"
            }
        )

    return techniques