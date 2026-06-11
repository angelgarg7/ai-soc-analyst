import requests

def get_ip_location(ip):

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )

        data = response.json()

        return {
            "ip": ip,
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "country": data.get("country"),
            "city": data.get("city")
        }

    except:
        return None