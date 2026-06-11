import requests
import os
import traceback
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv(
    "VT_API_KEY",
    ""
).strip()


# =========================
# Common VT Request Handler
# =========================

def vt_request(endpoint):

    if not VT_API_KEY:

        return {
            "error": "VirusTotal API key not found in .env file"
        }

    url = f"https://www.virustotal.com/api/v3/{endpoint}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:

            return response.json()

        if response.status_code == 401:

            return {
                "error": "Invalid VirusTotal API key"
            }

        if response.status_code == 429:

            return {
                "error": "VirusTotal API quota exceeded"
            }

        return {
            "error": f"VirusTotal API Error: {response.status_code}",
            "details": response.text
        }

    except Exception as e:

        print("\n===== VIRUSTOTAL ERROR =====")
        print(traceback.format_exc())
        print("=============================\n")

        return {
            "error": str(e)
        }


# =========================
# IP Reputation Check
# =========================

def check_ip(ip):

    data = vt_request(f"ip_addresses/{ip}")

    if "error" in data:
        return data

    stats = data["data"]["attributes"]["last_analysis_stats"]

    risk_score = (
        stats["malicious"] * 10 +
        stats["suspicious"] * 5
    )

    return {
        "type": "IP Address",
        "ioc": ip,
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "risk_score": risk_score,
        "status": get_risk_level(risk_score)
    }


# =========================
# Domain Reputation Check
# =========================

def check_domain(domain):

    data = vt_request(f"domains/{domain}")

    if "error" in data:
        return data

    stats = data["data"]["attributes"]["last_analysis_stats"]

    risk_score = (
        stats["malicious"] * 10 +
        stats["suspicious"] * 5
    )

    return {
        "type": "Domain",
        "ioc": domain,
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "risk_score": risk_score,
        "status": get_risk_level(risk_score)
    }


# =========================
# File Hash Reputation Check
# =========================

def check_hash(file_hash):

    data = vt_request(f"files/{file_hash}")

    if "error" in data:
        return data

    stats = data["data"]["attributes"]["last_analysis_stats"]

    risk_score = (
        stats["malicious"] * 10 +
        stats["suspicious"] * 5
    )

    return {
        "type": "File Hash",
        "ioc": file_hash,
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "risk_score": risk_score,
        "status": get_risk_level(risk_score)
    }


# =========================
# URL Reputation Check
# =========================

def check_url(url_value):

    data = vt_request(f"urls/{url_value}")

    if "error" in data:
        return data

    stats = data["data"]["attributes"]["last_analysis_stats"]

    risk_score = (
        stats["malicious"] * 10 +
        stats["suspicious"] * 5
    )

    return {
        "type": "URL",
        "ioc": url_value,
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "risk_score": risk_score,
        "status": get_risk_level(risk_score)
    }

# =========================
# Risk Level Logic
# =========================

def get_risk_level(score):

    if score >= 50:
        return "🔴 HIGH RISK"

    elif score >= 20:
        return "🟠 MEDIUM RISK"

    return "🟢 LOW RISK"