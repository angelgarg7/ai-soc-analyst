def detect_attacks(text):
    
    detections = []

    if not text:
        return detections

    text = str(text).lower()

    attack_patterns = {

        "SQLMAP DETECTED": [
            "sqlmap",
            "sqlmap/1.",
            "sql injection"
        ],

        "NMAP SCAN DETECTED": [
            "nmap",
            "nmap scripting engine"
        ],

        "ENCODED POWERSHELL DETECTED": [
            "encodedcommand",
            "powershell -encodedcommand"
        ],

        "MIMIKATZ DETECTED": [
            "mimikatz"
        ],

        "LOLBINS ABUSE DETECTED": [
            "certutil",
            "rundll32",
            "mshta",
            "regsvr32"
        ],

        "PERSISTENCE VIA SCHEDULED TASKS": [
            "schtasks"
        ],

        "POSSIBLE RDP ACTIVITY": [
            "mstsc",
            "remote desktop"
        ],

        "POWERSHELL EXECUTION": [
            "powershell"
        ],

        "CURL DOWNLOAD ACTIVITY": [
            "curl/",
            "curl "
        ],

        "WGET DOWNLOAD ACTIVITY": [
            "wget "
        ],

        "PSEXEC LATERAL MOVEMENT": [
            "psexec"
        ],

        "METERPRETER PAYLOAD": [
            "meterpreter"
        ],

        "SUSPICIOUS CMD EXECUTION": [
            "cmd.exe"
        ],

        "PORT SCANNING ACTIVITY": [
            "masscan",
            "zmap",
            "port scan"
        ]
    }

    for detection_name, keywords in attack_patterns.items():

        for keyword in keywords:

            if keyword in text:

                detections.append(detection_name)

                break

    return list(set(detections))