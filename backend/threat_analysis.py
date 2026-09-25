import ipaddress
from urllib.parse import urlparse


def analyze_threat(threat_type: str, threat_value: str) -> dict:
    threat_type = threat_type.strip().lower()
    threat_value = threat_value.strip()

    if not threat_value:
        return {
            "result": "Suspicious",
            "risk_level": "MEDIUM",
            "reason": "Threat value is empty or invalid.",
        }

    if threat_type == "ip":
        try:
            ipaddress.ip_address(threat_value)

            return {
                "result": "Safe",
                "risk_level": "LOW",
                "reason": "Valid IP address format detected.",
            }

        except ValueError:
            return {
                "result": "Suspicious",
                "risk_level": "MEDIUM",
                "reason": "Invalid IP address format.",
            }

    if threat_type == "url":
        parsed = urlparse(threat_value)

        if parsed.scheme in ("http", "https") and parsed.netloc:
            return {
                "result": "Suspicious",
                "risk_level": "MEDIUM",
                "reason": "Valid URL detected; further threat-intelligence checks are required.",
            }

        return {
            "result": "Suspicious",
            "risk_level": "MEDIUM",
            "reason": "Invalid URL format.",
        }

    if threat_type == "hash":
        valid_lengths = {32, 40, 64}

        if len(threat_value) in valid_lengths:
            try:
                int(threat_value, 16)

                return {
                    "result": "Suspicious",
                    "risk_level": "MEDIUM",
                    "reason": "Valid hexadecimal file-hash format detected.",
                }

            except ValueError:
                pass

        return {
            "result": "Suspicious",
            "risk_level": "MEDIUM",
            "reason": "Invalid file-hash format.",
        }

    return {
        "result": "Suspicious",
        "risk_level": "MEDIUM",
        "reason": "Unknown threat type.",
    }