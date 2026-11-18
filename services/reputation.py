"""
EmailRep Optional Reputation Service Adapter
Endpoint: https://emailrep.io/<email>
Uses EMAILREP_API_KEY from environment. Only activates when a valid key is provided.
"""

import os
import logging
import requests

logger = logging.getLogger("mailradar.reputation")

EMAILREP_BASE_URL = "https://emailrep.io/"
DEFAULT_TIMEOUT = 6.0  # 6 seconds timeout


def query_emailrep(email: str, api_key: str = None, session: requests.Session = None) -> dict:
    """
    Queries EmailRep API if an API key is explicitly configured.
    Per instructions:
      - Only activate when a valid, authorized API key is configured.
      - Use official API authentication requirements (Key header) and User-Agent header.
      - If no key is available, display: "Email reputation: Not configured."
      - Do not rely on unauthenticated access.
    """
    key = api_key or os.getenv("EMAILREP_API_KEY", "").strip()

    if not key:
        return {
            "status": "Not Configured",
            "is_configured": False,
            "message": "Email reputation: Not configured.",
            "data": None
        }

    requester = session or requests
    headers = {
        "Key": key,
        "User-Agent": "MailRadar-Security-Analyzer/1.0",
        "Accept": "application/json"
    }

    url = f"{EMAILREP_BASE_URL}{email.strip()}"

    try:
        response = requester.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)

        if response.status_code == 401 or response.status_code == 403:
            logger.warning("EmailRep API authentication failed: Invalid or expired key.")
            return {
                "status": "Invalid API Key",
                "is_configured": True,
                "message": "EmailRep authentication failed: Invalid API key.",
                "data": None
            }

        if response.status_code == 429:
            logger.warning("EmailRep API rate limit / quota exceeded.")
            return {
                "status": "Quota Exceeded",
                "is_configured": True,
                "message": "EmailRep API rate limit or quota exceeded.",
                "data": None
            }

        if response.status_code == 400:
            return {
                "status": "Invalid Query",
                "is_configured": True,
                "message": "EmailRep rejected query: Invalid email query format.",
                "data": None
            }

        if response.status_code != 200:
            return {
                "status": "API Error",
                "is_configured": True,
                "message": f"EmailRep API returned HTTP {response.status_code}",
                "data": None
            }

        data = response.json()

        # Parse actual EmailRep response fields
        reputation = data.get("reputation", "unknown")
        suspicious = data.get("suspicious", None)
        references = data.get("references", 0)
        details = data.get("details", {})

        return {
            "status": "Available",
            "is_configured": True,
            "message": "EmailRep reputation telemetry retrieved",
            "data": {
                "email": data.get("email", email),
                "reputation": reputation,
                "suspicious": suspicious,
                "references": references,
                "details": {
                    "blacklisted": details.get("blacklisted", None),
                    "malicious_activity": details.get("malicious_activity", None),
                    "credential_leaked": details.get("credential_leaked", None),
                    "data_breach": details.get("data_breach", None),
                    "spam": details.get("spam", None),
                    "first_seen": details.get("first_seen", None),
                    "last_seen": details.get("last_seen", None)
                }
            }
        }

    except requests.exceptions.Timeout:
        logger.warning(f"EmailRep query timed out for {email}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "message": "EmailRep request timed out.",
            "data": None
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"EmailRep connection error: {e}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "message": "Network failure connecting to EmailRep API.",
            "data": None
        }

