"""
Have I Been Pwned (HIBP) Breach Analysis Service
Integrates the official Have I Been Pwned API v3 breachedAccount endpoint.

Endpoint: GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
Headers:
  - hibp-api-key: [32-character hexadecimal key]
  - User-Agent: [consumer identifier]
Documentation: https://haveibeenpwned.com/API/v3
License: Creative Commons Attribution 4.0 International License
"""

import os
import urllib.parse
import logging
import requests
from typing import Optional, Dict, Any, List

from services.email_validator import validate_email_syntax

logger = logging.getLogger("mailradar.hibp")

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_TEST_KEY = "00000000000000000000000000000000"
DEFAULT_USER_AGENT = "MailRadar-Breach-Analyzer/1.0 (Windows NT 10.0; Win64; x64)"
DEFAULT_TIMEOUT = (5.0, 15.0)  # (connect timeout: 5s, read timeout: 15s)


def check_hibp_breaches(
    email: str,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
    user_authorized: bool = True,
    truncate_response: bool = False
) -> Dict[str, Any]:
    """
    Checks an email address against Have I Been Pwned (HIBP) v3 breachedAccount API.
    
    Requirements:
      - Email address must be supplied with user authorization.
      - hibp-api-key header must contain a valid 32-character hex key (or test key).
      - User-Agent header must be present.
      - Email address must be properly URL-encoded.
    
    Returns structured breach information:
      - status: Found, Not Found, Unauthorized, Forbidden, Rate Limited, Service Unavailable, etc.
      - breach_count: Number of breaches
      - breaches: List of breach objects (Name, Title, Domain, BreachDate, PwnCount, DataClasses, etc.)
      - attribution: Creative Commons Attribution statement
    """
    if not user_authorized:
        logger.warning(f"HIBP breach check aborted: User authorization not granted for {email}")
        return {
            "status": "Unauthorized Check",
            "is_configured": True,
            "breach_count": 0,
            "breaches": [],
            "source": "Have I Been Pwned",
            "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
            "message": "User authorization is required before querying breach databases.",
            "raw": None
        }

    # Validate email syntax before making network call
    syntax_res = validate_email_syntax(email)
    if not syntax_res["is_valid"]:
        return {
            "status": "Invalid Email",
            "is_configured": True,
            "breach_count": 0,
            "breaches": [],
            "source": "Have I Been Pwned",
            "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
            "message": f"Invalid email format: {syntax_res['error']}",
            "raw": None
        }

    email_clean = syntax_res["email"]
    domain = syntax_res["domain"].lower()

    # Determine API key: explicit param, env variable, or official test key for test accounts
    key = (api_key if api_key is not None else os.getenv("HIBP_API_KEY", "")).strip()

    # The official HIBP documentation allows using 00000000000000000000000000000000 on hibp-integration-tests.com
    if not key and domain == "hibp-integration-tests.com":
        key = HIBP_TEST_KEY
        logger.info(f"Using official HIBP test key for integration test domain: {domain}")

    if not key:
        return {
            "status": "Not Configured",
            "is_configured": False,
            "breach_count": 0,
            "breaches": [],
            "source": "Have I Been Pwned",
            "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
            "message": "HIBP_API_KEY not configured in environment.",
            "raw": None
        }

    # URL-encode the email address
    encoded_email = urllib.parse.quote(email_clean)
    truncate_flag = "true" if truncate_response else "false"
    url = f"{HIBP_BASE_URL}/breachedaccount/{encoded_email}?truncateResponse={truncate_flag}"

    headers = {
        "hibp-api-key": key,
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "application/json"
    }

    requester = session or requests

    try:
        response = requester.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        status_code = response.status_code

        # HTTP 200: Breach(es) found
        if status_code == 200:
            raw_breaches = response.json()
            if not isinstance(raw_breaches, list):
                raw_breaches = [raw_breaches]

            parsed_breaches = []
            for b in raw_breaches:
                parsed_breaches.append({
                    "name": b.get("Name", "Unknown"),
                    "title": b.get("Title") or b.get("Name", "Unknown"),
                    "domain": b.get("Domain", ""),
                    "breach_date": b.get("BreachDate", "Unknown"),
                    "added_date": b.get("AddedDate"),
                    "modified_date": b.get("ModifiedDate"),
                    "pwn_count": b.get("PwnCount", 0),
                    "description": b.get("Description", ""),
                    "data_classes": b.get("DataClasses") or [],
                    "is_verified": b.get("IsVerified", True),
                    "is_fabricated": b.get("IsFabricated", False),
                    "is_sensitive": b.get("IsSensitive", False),
                    "is_spam_list": b.get("IsSpamList", False),
                    "is_malware": b.get("IsMalware", False),
                    "is_stealer_log": b.get("IsStealerLog", False),
                    "logo_path": b.get("LogoPath", "")
                })

            logger.info(f"HIBP query for {email_clean}: {len(parsed_breaches)} breach(es) found.")
            return {
                "status": "Found",
                "is_configured": True,
                "breach_count": len(parsed_breaches),
                "breaches": parsed_breaches,
                "source": "Have I Been Pwned",
                "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com) under Creative Commons Attribution 4.0 International License",
                "message": f"{len(parsed_breaches)} publicly disclosed breach record(s) found.",
                "raw": raw_breaches
            }

        # HTTP 404: No publicly listed breaches found
        if status_code == 404:
            logger.info(f"HIBP query for {email_clean}: No breaches found (HTTP 404).")
            return {
                "status": "Not Found",
                "is_configured": True,
                "breach_count": 0,
                "breaches": [],
                "source": "Have I Been Pwned",
                "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
                "message": "No publicly disclosed breach records found for this account on Have I Been Pwned.",
                "raw": []
            }

        # HTTP 401: Unauthorized (missing or invalid API key)
        if status_code == 401:
            err_msg = "Unauthorised: Missing or invalid hibp-api-key (32-character hexadecimal key required)."
            logger.warning(f"HIBP query failed 401: {err_msg}")
            return {
                "status": "Unauthorized",
                "is_configured": True,
                "breach_count": 0,
                "breaches": [],
                "source": "Have I Been Pwned",
                "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
                "message": err_msg,
                "raw": None
            }

        # HTTP 403: Forbidden (missing user-agent or forbidden resource)
        if status_code == 403:
            err_msg = "Forbidden: Access denied by Have I Been Pwned (check User-Agent header or plan permissions)."
            logger.warning(f"HIBP query failed 403: {err_msg}")
            return {
                "status": "Forbidden",
                "is_configured": True,
                "breach_count": 0,
                "breaches": [],
                "source": "Have I Been Pwned",
                "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
                "message": err_msg,
                "raw": None
            }

        # HTTP 429: Too Many Requests (Rate limit exceeded)
        if status_code == 429:
            retry_after = response.headers.get("retry-after", "2")
            err_msg = f"Rate limit exceeded. Please retry after {retry_after} second(s)."
            logger.warning(f"HIBP query 429 rate limit: retry after {retry_after}s")
            return {
                "status": "Rate Limited",
                "is_configured": True,
                "breach_count": 0,
                "breaches": [],
                "retry_after": retry_after,
                "source": "Have I Been Pwned",
                "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
                "message": err_msg,
                "raw": None
            }

        # HTTP 503: Service Unavailable (Cloudflare / upstream down)
        if status_code == 503:
            err_msg = "Have I Been Pwned service is temporarily unavailable (Cloudflare 503)."
            logger.warning(f"HIBP 503 Service Unavailable for {email_clean}")
            return {
                "status": "Service Unavailable",
                "is_configured": True,
                "breach_count": 0,
                "breaches": [],
                "source": "Have I Been Pwned",
                "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
                "message": err_msg,
                "raw": None
            }

        logger.error(f"HIBP returned unexpected HTTP {status_code}: {response.text}")
        return {
            "status": "API Error",
            "is_configured": True,
            "breach_count": 0,
            "breaches": [],
            "source": "Have I Been Pwned",
            "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
            "message": f"Have I Been Pwned returned HTTP {status_code}",
            "raw": None
        }

    except requests.exceptions.Timeout:
        logger.warning(f"HIBP request timed out for {email_clean}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "breach_count": 0,
            "breaches": [],
            "source": "Have I Been Pwned",
            "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
            "message": "Have I Been Pwned API connection timed out.",
            "raw": None
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"HIBP request network error for {email_clean}: {e}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "breach_count": 0,
            "breaches": [],
            "source": "Have I Been Pwned",
            "attribution": "Data provided by Have I Been Pwned (haveibeenpwned.com)",
            "message": "Network failure connecting to Have I Been Pwned API.",
            "raw": None
        }
