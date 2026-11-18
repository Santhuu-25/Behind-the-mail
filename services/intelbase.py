"""
IntelBase API Integration Service
Provides real-time OSINT intelligence, data breaches, infostealer logs,
account detections, and credential exposure scores for investigated email targets.

Endpoints:
  - POST https://api.intelbase.is/lookup/email
  - POST https://api.intelbase.is/lookup/username
  - GET  https://api.intelbase.is/lookup/modules
  - GET  https://api.intelbase.is/account/ip

Reference: https://intelbase.is/docs
"""

import os
import re
import logging
import requests
from typing import Optional, Dict, Any, List

from services.email_validator import validate_email_syntax

logger = logging.getLogger("mailradar.intelbase")

INTELBASE_BASE_URL = "https://api.intelbase.is"
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 25.0


def get_intelbase_egress_ip(session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Public unauthenticated helper that queries IntelBase's /account/ip
    to determine the current egress IP address needed for API whitelisting.
    """
    requester = session or requests
    url = f"{INTELBASE_BASE_URL}/account/ip"
    try:
        resp = requester.get(url, timeout=DEFAULT_CONNECT_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            ip_val = data.get("ip", "")
            return {
                "success": True,
                "ip": ip_val,
                "whitelisted_info": f"Add {ip_val} to your IP whitelist at https://intelbase.is/dashboard",
                "raw": data
            }
        return {
            "success": False,
            "error": f"HTTP {resp.status_code}: {resp.text}"
        }
    except Exception as e:
        logger.warning(f"Failed to query IntelBase egress IP: {e}")
        return {
            "success": False,
            "error": str(e)
        }


def query_intelbase_email(
    email: str,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
    timeout_ms: int = 10000,
    include_data_breaches: bool = True,
    include_stealer_logs: bool = True,
    include_ai: bool = False,
    exclude_modules: Optional[List[str]] = None,
    include_modules: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Queries the official IntelBase Email Lookup API in real time.
    Endpoint: POST https://api.intelbase.is/lookup/email
    Header: x-api-key: YOUR_API_KEY

    Returns rich threat intelligence:
      - identifier.accounts: Connected accounts and profile metadata (Google, Spotify, etc.)
      - validator.registered: Confirmed platforms registered with this email
      - validator.unregistered: Services checked where not registered
      - data_breaches: Compromised credential breaches, dates, source names
      - stealer_logs: Infostealer malware infections and compromised logs
      - stealer_enrichment: Aggregated infostealer intelligence (autofill, user_info, etc.)
      - suggestions: Search next candidates
      - insights.score: Authenticity & Exposure scores (0-100)
      - insights.password_reuse: Password repetition across leaks
      - insights.domain: Domain intelligence from public DNS and lists
      - meta: Timeline of account creation and breach events
    """
    key = (api_key if api_key is not None else os.getenv("INTELBASE_API_KEY", "")).strip()

    if not key:
        return {
            "status": "Not Configured",
            "is_configured": False,
            "message": "IntelBase API key not configured in environment.",
            "data": None,
            "raw": None
        }

    # Validate email syntax before making the network request
    syntax_res = validate_email_syntax(email)
    if not syntax_res["is_valid"]:
        return {
            "status": "Invalid Email",
            "is_configured": True,
            "message": f"Syntax invalid ({syntax_res['error']}); IntelBase query aborted.",
            "data": None,
            "raw": None
        }

    email_clean = syntax_res["email"]
    requester = session or requests
    url = f"{INTELBASE_BASE_URL}/lookup/email"

    headers = {
        "x-api-key": key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "MailRadar-OSINT/2.0"
    }

    payload = {
        "email": email_clean,
        "timeout_ms": max(100, min(timeout_ms, 120000)),
        "include_data_breaches": bool(include_data_breaches),
        "include_stealer_logs": bool(include_stealer_logs),
        "include_ai": bool(include_ai)
    }

    if exclude_modules and isinstance(exclude_modules, list):
        payload["exclude_modules"] = exclude_modules
    elif include_modules and isinstance(include_modules, list):
        payload["include_modules"] = include_modules

    # Dynamically scale timeout to allow server to finish within timeout_ms
    read_timeout = max(DEFAULT_READ_TIMEOUT, (timeout_ms / 1000.0) + 5.0)

    try:
        response = requester.post(
            url,
            headers=headers,
            json=payload,
            timeout=(DEFAULT_CONNECT_TIMEOUT, read_timeout)
        )

        status_code = response.status_code

        # HTTP 401: Unauthorized (Invalid Key, Non-Whitelisted IP, Free Plan, or Daily Quota Exceeded)
        if status_code == 401:
            err_msg = "Unauthorized: Invalid API key, unwhitelisted IP, or daily quota exceeded."
            try:
                err_json = response.json()
                if "error" in err_json:
                    err_msg = err_json["error"]
            except Exception:
                if response.text:
                    err_msg = response.text

            logger.warning(f"IntelBase API 401: {err_msg}")
            return {
                "status": "Unauthorized",
                "is_configured": True,
                "message": f"IntelBase authorization failed: {err_msg}",
                "data": None,
                "raw": {"status_code": 401, "error": err_msg}
            }

        # HTTP 403: Forbidden (Target email blacklisted from lookups)
        if status_code == 403:
            logger.info(f"Target email {email_clean} is blacklisted on IntelBase.")
            return {
                "status": "Blacklisted Target",
                "is_configured": True,
                "message": "Target address has requested exclusion from IntelBase intelligence records.",
                "data": None,
                "raw": {"status_code": 403, "error": "Email is blacklisted"}
            }

        # HTTP 429: Too Many Requests (Rate limit exceeded)
        if status_code == 429:
            logger.warning("IntelBase API rate limit exceeded.")
            return {
                "status": "Quota Exceeded",
                "is_configured": True,
                "message": "IntelBase API rate limit or plan limit reached.",
                "data": None,
                "raw": {"status_code": 429, "error": "Too Many Requests"}
            }

        # HTTP 400: Bad Request
        if status_code == 400:
            err_msg = response.text
            try:
                err_msg = response.json().get("error", err_msg)
            except Exception:
                pass
            return {
                "status": "Bad Request",
                "is_configured": True,
                "message": f"IntelBase rejected request: {err_msg}",
                "data": None,
                "raw": {"status_code": 400, "error": err_msg}
            }

        if status_code != 200:
            logger.error(f"IntelBase API returned HTTP {status_code}: {response.text}")
            return {
                "status": "API Error",
                "is_configured": True,
                "message": f"IntelBase returned HTTP {status_code}",
                "data": None,
                "raw": {"status_code": status_code, "text": response.text}
            }

        data = response.json()

        # Parse primary telemetry fields
        identifier = data.get("identifier") or {}
        accounts = identifier.get("accounts") or []
        validator = data.get("validator") or {}
        registered_services = validator.get("registered") or []
        unregistered_services = validator.get("unregistered") or []

        data_breaches = data.get("data_breaches") or {}
        stealer_logs = data.get("stealer_logs") or {}
        stealer_enrichment = data.get("stealer_enrichment")
        suggestions = data.get("suggestions") or {}
        insights = data.get("insights") or {}
        identity = data.get("identity")
        meta = data.get("meta") or {}

        # Synthesize exposure & authenticity insights
        score_info = insights.get("score") or {}
        authenticity = score_info.get("authenticity") or {}
        exposure = score_info.get("exposure") or {}

        parsed_data = {
            "email": email_clean,
            "accounts_count": len(accounts),
            "accounts": accounts,
            "registered_platforms": [
                {
                    "name": s.get("name_formatted") or s.get("name"),
                    "domain": s.get("domain"),
                    "id": s.get("id"),
                    "type": s.get("type")
                }
                for s in registered_services
            ],
            "registered_count": len(registered_services),
            "unregistered_count": len(unregistered_services),
            "unregistered_platforms": [
                {
                    "name": s.get("name_formatted") or s.get("name"),
                    "domain": s.get("domain")
                }
                for s in unregistered_services
            ],
            "breaches": {
                "amount": data_breaches.get("amount", 0),
                "sources_count": data_breaches.get("sources", 0),
                "redacted": data_breaches.get("redacted", False),
                "partially_redacted": data_breaches.get("partially_redacted", False),
                "results": data_breaches.get("results", [])
            },
            "stealer_logs": {
                "count": stealer_logs.get("count", 0),
                "compromised": stealer_logs.get("compromised", False),
                "has_stealer_log_type": stealer_logs.get("has_stealer_log_type", False),
                "redacted": stealer_logs.get("redacted", False),
                "results": stealer_logs.get("results", [])
            },
            "stealer_enrichment": stealer_enrichment,
            "suggestions": suggestions,
            "authenticity_score": authenticity.get("score"),
            "authenticity_band": authenticity.get("band"),
            "exposure_score": exposure.get("score"),
            "exposure_band": exposure.get("band"),
            "password_reuse": insights.get("password_reuse"),
            "domain_insights": insights.get("domain"),
            "identity": identity,
            "first_seen": meta.get("first_seen"),
            "last_seen": meta.get("last_seen"),
            "timeline": meta.get("timeline", [])
        }

        return {
            "status": "Available",
            "is_configured": True,
            "message": "IntelBase real-time OSINT profile retrieved successfully",
            "data": parsed_data,
            "raw": data
        }

    except requests.exceptions.Timeout:
        logger.warning(f"IntelBase API request timed out for {email_clean}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "message": f"IntelBase API request timed out (exceeded {read_timeout:.1f}s).",
            "data": None,
            "raw": None
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"IntelBase API network error: {e}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "message": "Network failure connecting to IntelBase API.",
            "data": None,
            "raw": None
        }


def query_intelbase_username(
    username: str,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
    timeout_ms: int = 15000,
    include_ai: bool = False,
    exclude_modules: Optional[List[str]] = None,
    include_modules: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Checks a username across hundreds of sites via IntelBase.
    Endpoint: POST https://api.intelbase.is/lookup/username
    Header: x-api-key: YOUR_API_KEY
    """
    key = (api_key if api_key is not None else os.getenv("INTELBASE_API_KEY", "")).strip()

    if not key:
        return {
            "status": "Not Configured",
            "is_configured": False,
            "message": "IntelBase API key not configured.",
            "data": None
        }

    clean_user = username.strip().lstrip("@")
    if not clean_user or not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,64}$", clean_user):
        return {
            "status": "Invalid Username",
            "is_configured": True,
            "message": "Username must be 1-65 characters starting with an alphanumeric character.",
            "data": None
        }

    requester = session or requests
    url = f"{INTELBASE_BASE_URL}/lookup/username"

    headers = {
        "x-api-key": key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "MailRadar-OSINT/2.0"
    }

    payload = {
        "username": clean_user,
        "timeout_ms": max(100, min(timeout_ms, 120000)),
        "include_ai": bool(include_ai)
    }

    if exclude_modules and isinstance(exclude_modules, list):
        payload["exclude_modules"] = exclude_modules
    elif include_modules and isinstance(include_modules, list):
        payload["include_modules"] = include_modules

    read_timeout = max(DEFAULT_READ_TIMEOUT, (timeout_ms / 1000.0) + 15.0)

    try:
        resp = requester.post(
            url,
            headers=headers,
            json=payload,
            timeout=(DEFAULT_CONNECT_TIMEOUT, read_timeout)
        )

        if resp.status_code == 200:
            data = resp.json()
            return {
                "status": "Available",
                "is_configured": True,
                "message": "Username intelligence retrieved successfully",
                "data": data,
                "raw": data
            }
        elif resp.status_code == 401:
            return {
                "status": "Unauthorized",
                "is_configured": True,
                "message": "IntelBase 401: Invalid key or unwhitelisted IP",
                "data": None
            }
        else:
            return {
                "status": f"HTTP {resp.status_code}",
                "is_configured": True,
                "message": resp.text,
                "data": None
            }
    except Exception as e:
        logger.error(f"IntelBase username lookup error: {e}")
        return {
            "status": "API Error",
            "is_configured": True,
            "message": str(e),
            "data": None
        }


def get_intelbase_modules(
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None
) -> Dict[str, Any]:
    """
    Lists the available modules for lookups.
    Endpoint: GET https://api.intelbase.is/lookup/modules
    Header: x-api-key: YOUR_API_KEY
    """
    key = (api_key if api_key is not None else os.getenv("INTELBASE_API_KEY", "")).strip()
    if not key:
        return {
            "status": "Not Configured",
            "is_configured": False,
            "message": "IntelBase API key not configured.",
            "data": None
        }

    requester = session or requests
    url = f"{INTELBASE_BASE_URL}/lookup/modules"
    headers = {
        "x-api-key": key,
        "Accept": "application/json"
    }

    try:
        resp = requester.get(url, headers=headers, timeout=DEFAULT_CONNECT_TIMEOUT)
        if resp.status_code == 200:
            return {
                "status": "Available",
                "is_configured": True,
                "data": resp.json()
            }
        return {
            "status": f"HTTP {resp.status_code}",
            "is_configured": True,
            "message": resp.text,
            "data": None
        }
    except Exception as e:
        return {
            "status": "API Error",
            "is_configured": True,
            "message": str(e),
            "data": None
        }
