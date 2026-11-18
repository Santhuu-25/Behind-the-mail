"""
Email Validator & Abstract Email Reputation API Integration Service
Validates email syntax RFC compliance and interfaces with Abstract Email Reputation API.
Endpoint: https://emailreputation.abstractapi.com/v1/
"""

import os
import re
import logging
import requests

logger = logging.getLogger("mailradar.validator")

ABSTRACT_REPUTATION_URL = "https://emailreputation.abstractapi.com/v1/"
DEFAULT_TIMEOUT = (4.0, 8.0)  # (connect timeout: 4s, read timeout: 8s)

# Standard RFC 5322 compliant email regex pattern
EMAIL_REGEX = re.compile(
    r"^(?!\.)[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$"
)


def validate_email_syntax(email: str) -> dict:
    """
    Validates email format against RFC 5322 requirements.
    Performs length constraints, character set, and domain sanity checks.
    """
    if not email or not isinstance(email, str):
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": None,
            "domain": None,
            "error": "Email address cannot be empty"
        }

    email_clean = email.strip()

    # Total length check (RFC 5321: path maximum is 254 characters)
    if len(email_clean) > 254:
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": None,
            "domain": None,
            "error": "Email length exceeds maximum limit of 254 characters"
        }

    # Must contain exactly one @ symbol
    if email_clean.count("@") != 1:
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": None,
            "domain": None,
            "error": "Email must contain exactly one '@' symbol separating local part and domain"
        }

    local_part, domain = email_clean.split("@", 1)

    # Local part length check (RFC 5321: local part max 64 characters)
    if len(local_part) == 0:
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": "",
            "domain": domain,
            "error": "Local mailbox part before '@' cannot be empty"
        }

    if len(local_part) > 64:
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": local_part,
            "domain": domain,
            "error": f"Local part exceeds maximum of 64 characters ({len(local_part)} chars)"
        }

    # Domain length check (RFC 1035: domain name max 255 characters)
    if len(domain) == 0:
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": local_part,
            "domain": "",
            "error": "Domain part after '@' cannot be empty"
        }

    if len(domain) > 255:
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": local_part,
            "domain": domain,
            "error": "Domain name exceeds maximum length of 255 characters"
        }

    # Check for consecutive dots
    if ".." in email_clean:
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": local_part,
            "domain": domain,
            "error": "Email contains illegal consecutive dots ('..')"
        }

    # Check for leading/trailing dots in local part
    if local_part.startswith(".") or local_part.endswith("."):
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": local_part,
            "domain": domain,
            "error": "Local part cannot start or end with a dot"
        }

    # Check domain label format
    labels = domain.split(".")
    if len(labels) < 2:
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": local_part,
            "domain": domain,
            "error": "Domain must contain at least one top-level domain label (e.g., .com)"
        }

    tld = labels[-1]
    # Strict TLD check: must be strictly alphabetic and between 2 and 63 characters (RFC 1035)
    if not re.match(r"^[A-Za-z]{2,63}$", tld):
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": local_part,
            "domain": domain,
            "error": f"Top-level domain (TLD) '.{tld}' is invalid. TLD must consist of at least 2 alphabetic characters."
        }

    for label in labels:
        if not label:
            return {
                "status": "Invalid",
                "is_valid": False,
                "local_part": local_part,
                "domain": domain,
                "error": "Domain contains an empty or malformed label"
            }
        if len(label) > 63:
            return {
                "status": "Invalid",
                "is_valid": False,
                "local_part": local_part,
                "domain": domain,
                "error": "Domain label exceeds maximum 63 characters"
            }
        if label.startswith("-") or label.endswith("-"):
            return {
                "status": "Invalid",
                "is_valid": False,
                "local_part": local_part,
                "domain": domain,
                "error": "Domain labels cannot start or end with a hyphen"
            }

    # Regex validation
    if not EMAIL_REGEX.match(email_clean):
        return {
            "status": "Invalid",
            "is_valid": False,
            "local_part": local_part,
            "domain": domain,
            "error": "Email contains characters or format not adhering to standard email syntax"
        }

    return {
        "status": "Valid",
        "is_valid": True,
        "email": email_clean,
        "local_part": local_part,
        "domain": domain.lower(),
        "error": None
    }


def check_email_reputation(email: str, api_key: str = None, session: requests.Session = None) -> dict:
    """
    Calls the official Abstract Email Reputation API.
    Endpoint: https://emailreputation.abstractapi.com/v1/

    Authentication:
      api_key passed as query parameter (read from ABSTRACT_API_KEY environment variable).

    Response handling:
      - Validates email format before querying.
      - Enforces connection & read timeouts.
      - Handles 401/403 (Invalid API Key), 429 (Quota Exceeded), HTTP errors, timeouts, and network failures.
      - Parses official fields: email_deliverability, email_quality, email_sender, email_domain,
        email_risk, email_breaches.
      - Returns structured data without fabricating scores.
    """
    key = (api_key if api_key is not None else os.getenv("ABSTRACT_API_KEY", "")).strip()

    if not key:
        return {
            "status": "Not Configured",
            "is_configured": False,
            "message": "Abstract Email Reputation API key not configured in environment.",
            "data": None
        }

    # Validate email syntax before making the network request
    syntax_res = validate_email_syntax(email)
    if not syntax_res["is_valid"]:
        return {
            "status": "Invalid Email",
            "is_configured": True,
            "message": f"Syntax invalid ({syntax_res['error']}); API query aborted.",
            "data": None
        }

    email_clean = syntax_res["email"]
    requester = session or requests
    params = {
        "api_key": key,
        "email": email_clean
    }

    try:
        response = requester.get(
            ABSTRACT_REPUTATION_URL,
            params=params,
            timeout=DEFAULT_TIMEOUT
        )

        status_code = response.status_code

        # HTTP 401 / 403: Invalid API Key or Unauthorized
        if status_code in (401, 403):
            logger.warning("Abstract API Key unauthorized or invalid.")
            return {
                "status": "Invalid API Key",
                "is_configured": True,
                "message": "Abstract API authentication failed: Invalid or expired API key.",
                "data": None
            }

        # HTTP 429: Rate Limit / Free Quota Exhausted
        if status_code == 429:
            logger.warning("Abstract API rate limit or quota exceeded.")
            return {
                "status": "Quota Exceeded",
                "is_configured": True,
                "message": "Abstract API quota exceeded or rate limit reached.",
                "data": None
            }

        if status_code != 200:
            logger.error(f"Abstract API returned HTTP {status_code}: {response.text}")
            return {
                "status": "API Error",
                "is_configured": True,
                "message": f"Abstract API returned HTTP {status_code}",
                "data": None
            }

        data = response.json()

        # Check for error payload inside JSON (Abstract may return 200 with error structure)
        if isinstance(data, dict) and "error" in data:
            err_msg = data.get("error", {}).get("message", "Unknown error from Abstract API")
            err_code = str(data.get("error", {}).get("code", "")).lower()
            if "quota" in err_code or "quota" in err_msg.lower():
                return {
                    "status": "Quota Exceeded",
                    "is_configured": True,
                    "message": f"Abstract API quota exhausted: {err_msg}",
                    "data": None
                }
            if "unauthorized" in err_code or "api key" in err_msg.lower() or "invalid" in err_msg.lower():
                return {
                    "status": "Invalid API Key",
                    "is_configured": True,
                    "message": f"Abstract API authentication failed: {err_msg}",
                    "data": None
                }
            return {
                "status": "API Error",
                "is_configured": True,
                "message": f"Abstract API error: {err_msg}",
                "data": None
            }

        # Parse official JSON response blocks per Abstract Email Reputation API schema
        deliv = data.get("email_deliverability") or {}
        quality = data.get("email_quality") or {}
        sender = data.get("email_sender") or {}
        domain_info = data.get("email_domain") or {}
        risk = data.get("email_risk") or {}
        breaches = data.get("email_breaches") or {}

        deliverability_status = (deliv.get("status") or "UNKNOWN").upper()

        quality_score = quality.get("score")
        if quality_score is not None:
            try:
                quality_score = float(quality_score)
            except (ValueError, TypeError):
                quality_score = None

        is_smtp_valid = deliv.get("is_smtp_valid")
        is_free_email = quality.get("is_free_email")
        is_disposable = quality.get("is_disposable")

        parsed_data = {
            "email_address": data.get("email_address", email_clean),
            "suggested_correction": data.get("suggested_correction"),
            "email_deliverability": {
                "status": deliv.get("status", "unknown"),
                "status_detail": deliv.get("status_detail", ""),
                "is_format_valid": deliv.get("is_format_valid"),
                "is_smtp_valid": is_smtp_valid,
                "is_mx_valid": deliv.get("is_mx_valid"),
                "mx_records": deliv.get("mx_records", [])
            },
            "email_quality": {
                "score": quality_score,
                "is_free_email": is_free_email,
                "is_username_suspicious": quality.get("is_username_suspicious"),
                "is_disposable": is_disposable,
                "is_catchall": quality.get("is_catchall"),
                "is_subaddress": quality.get("is_subaddress"),
                "is_role": quality.get("is_role"),
                "is_dmarc_enforced": quality.get("is_dmarc_enforced"),
                "is_spf_strict": quality.get("is_spf_strict"),
                "minimum_age": quality.get("minimum_age")
            },
            "email_sender": {
                "first_name": sender.get("first_name"),
                "last_name": sender.get("last_name"),
                "email_provider_name": sender.get("email_provider_name"),
                "organization_name": sender.get("organization_name"),
                "organization_type": sender.get("organization_type")
            },
            "email_domain": {
                "domain": domain_info.get("domain"),
                "domain_age": domain_info.get("domain_age"),
                "is_live_site": domain_info.get("is_live_site"),
                "registrar": domain_info.get("registrar"),
                "date_registered": domain_info.get("date_registered"),
                "is_risky_tld": domain_info.get("is_risky_tld")
            },
            "email_risk": {
                "address_risk_status": risk.get("address_risk_status", "unknown"),
                "domain_risk_status": risk.get("domain_risk_status", "unknown")
            },
            "email_breaches": {
                "total_breaches": breaches.get("total_breaches", 0),
                "date_first_breached": breaches.get("date_first_breached"),
                "date_last_breached": breaches.get("date_last_breached"),
                "breached_domains": breaches.get("breached_domains", [])
            },
            # Compatibility helpers for UI components
            "deliverability": deliverability_status if deliverability_status != "UNKNOWN" else "Unavailable",
            "quality_score": quality_score,
            "is_smtp_valid": {
                "value": is_smtp_valid,
                "label": "Accepted by Mail Server (Handshake)" if is_smtp_valid is True else ("Rejected by Mail Server" if is_smtp_valid is False else "Unavailable")
            },
            "is_free_email": {
                "value": is_free_email,
                "label": "Free Webmail Provider" if is_free_email is True else ("Custom / Corporate Domain" if is_free_email is False else "Unavailable")
            },
            "is_disposable_email": {
                "value": is_disposable,
                "label": "Disposable (Temporary)" if is_disposable is True else ("Non-Disposable" if is_disposable is False else "Unavailable")
            }
        }

        return {
            "status": "Available",
            "is_configured": True,
            "message": "Abstract Email Reputation API responded successfully",
            "data": parsed_data
        }

    except requests.exceptions.Timeout:
        logger.warning(f"Abstract Email Reputation API request timed out for {email}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "message": "Abstract Email Reputation API request timed out (exceeded 8.0s).",
            "data": None
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Abstract Email Reputation API connection error: {e}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "message": "Network failure connecting to Abstract Email Reputation API.",
            "data": None
        }


# Alias for backward-compatibility with existing imports/tests
query_abstract_api = check_email_reputation
