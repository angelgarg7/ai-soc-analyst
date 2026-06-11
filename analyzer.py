from openai import OpenAI
from dotenv import load_dotenv
import os
import traceback

# Load environment variables
load_dotenv()

# OpenAI model
MODEL_NAME = os.getenv(
    "OPENAI_MODEL",
    "gpt-4o-mini"
).strip()

# Read API key from .env
API_KEY = os.getenv(
    "OPENAI_API_KEY",
    ""
).strip()

# Validate API key
if not API_KEY:
    raise ValueError(
        "OPENAI_API_KEY not found in .env file"
    )

# Configure OpenAI client
client = OpenAI(api_key=API_KEY)


def analyze_logs(log_text):

    # Limit extremely large logs
    safe_logs = str(log_text)[:12000]

    prompt = f"""
You are an expert SOC analyst.

Analyze these security logs carefully.

Identify:
- suspicious activity
- malware indicators
- persistence mechanisms
- credential theft
- unusual PowerShell activity
- lateral movement
- suspicious IP addresses
- malicious domains
- attacker behavior

Provide:
1. Incident Summary
2. Severity Level
3. Indicators of Compromise (IOCs)
4. MITRE ATT&CK Techniques
5. Recommended Actions

Logs:
{safe_logs}
"""

    try:

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": "You are an elite SOC analyst and cybersecurity threat hunter."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=1200
        )

        result = response.choices[0].message.content

        if not result:
            return "No AI analysis generated."

        return str(result).strip()

    except Exception as e:

        error_message = str(e)

        print("\n===== OPENAI ERROR =====")
        print(traceback.format_exc())
        print("========================\n")

        if "429" in error_message:
            return "🚫 OpenAI API quota exceeded. Please check billing or wait before retrying."

        if "incorrect_api_key" in error_message.lower() or "invalid_api_key" in error_message.lower():
            return "❌ Invalid OpenAI API key. Please verify your .env configuration."

        if "insufficient_quota" in error_message.lower():
            return "⚠️ OpenAI quota exhausted. Please add billing or generate a new API key."

        if "model" in error_message.lower() and "not found" in error_message.lower():
            return "⚠️ OpenAI model not found. Please verify the model name in your .env file."

        return f"❌ Error during AI analysis: {error_message}"