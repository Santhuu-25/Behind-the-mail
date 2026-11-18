"""
Behind the Email (BTE) API Integration Service
Calls POST https://api.behindtheemail.com/v1/search with Bearer Token.
Strictly parses authentic responses; zero simulated or mock data generation.
"""

import os
import logging
import requests
from typing import Optional, Dict, Any, List

from services.email_validator import validate_email_syntax

logger = logging.getLogger("mailradar.bte")

BTE_BASE_URL = "https://api.behindtheemail.com/v1"
BTE_DEFAULT_TIMEOUT = (4.0, 15.0)


def check_bte_api_health(api_key: Optional[str] = None, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Checks Behind the Email API version and availability.
    GET https://api.behindtheemail.com/v1
    """
    token = (api_key if api_key is not None else os.getenv("BEHIND_THE_EMAIL_API_KEY", "")).strip()
    requester = session or requests
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    try:
        resp = requester.get(BTE_BASE_URL, headers=headers, timeout=6.0)
        if resp.status_code == 200:
            return {"success": True, "data": resp.json().get("data", {})}
        return {"success": False, "status_code": resp.status_code, "error": resp.text}
    except Exception as e:
        logger.warning(f"Behind the Email health probe failed: {e}")
        return {"success": False, "error": str(e)}


def query_behind_the_email(
    email: str,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
    selected_providers: Optional[List[str]] = None,
    excluded_providers: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Calls POST https://api.behindtheemail.com/v1/search.
    Returns real public profile intelligence if authorized.
    Returns clean empty state if route requires paid subscription or target not found.
    """
    token = (api_key if api_key is not None else os.getenv("BEHIND_THE_EMAIL_API_KEY", "")).strip()

    if not token:
        return {
            "status": "Not Configured",
            "is_configured": False,
            "message": "Behind the Email API key not configured.",
            "data": None
        }

    # Validate email syntax
    syntax_res = validate_email_syntax(email)
    if not syntax_res["is_valid"]:
        return {
            "status": "Invalid Email",
            "is_configured": True,
            "message": f"Syntax invalid ({syntax_res['error']}); query aborted.",
            "data": None
        }

    email_clean = syntax_res["email"].lower()
    requester = session or requests
    url = f"{BTE_BASE_URL}/search"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "MailRadar-OSINT/1.0"
    }

    payload = {"email": email_clean}
    if selected_providers:
        payload["selectedProviders"] = selected_providers
    if excluded_providers:
        payload["excludedProviders"] = excluded_providers

    try:
        response = requester.post(
            url,
            headers=headers,
            json=payload,
            timeout=BTE_DEFAULT_TIMEOUT
        )

        status_code = response.status_code

        # HTTP 200: Real profile data returned
        if status_code == 200:
            res_json = response.json()
            data_body = res_json.get("data") or {}
            profile = data_body.get("profile") or {}
            status_text = data_body.get("status", "found")

            parsed = _parse_bte_profile(email_clean, status_text, profile)
            return {
                "status": "Available",
                "is_configured": True,
                "message": "Behind the Email profile retrieved successfully",
                "data": parsed
            }

        # HTTP 401: Unauthorized / Free plan restriction
        if status_code == 401:
            err_data = {}
            try:
                err_data = response.json().get("error", {})
            except Exception:
                pass
            msg = err_data.get("message") or "Unauthorized: Invalid key or route restricted to paid API plans."
            logger.info(f"Behind the Email API 401: {msg}")

            return {
                "status": "Plan Restricted (Free Plan)",
                "is_configured": True,
                "message": f"Behind the Email: {msg}",
                "data": None
            }

        if status_code == 404:
            return {
                "status": "Not Found",
                "is_configured": True,
                "message": "No profile found for target address on Behind the Email.",
                "data": None
            }

        # HTTP 429: Rate limited
        if status_code == 429:
            return {
                "status": "Quota Exceeded",
                "is_configured": True,
                "message": "Behind the Email API rate limit reached.",
                "data": None
            }

        return {
            "status": "API Error",
            "is_configured": True,
            "message": f"Behind the Email returned HTTP {status_code}",
            "data": None
        }

    except requests.exceptions.Timeout:
        logger.warning(f"Behind the Email request timed out for {email_clean}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "message": "Behind the Email request timed out.",
            "data": None
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Behind the Email network error: {e}")
        return {
            "status": "API Unavailable",
            "is_configured": True,
            "message": f"Connection error: {e}",
            "data": None
        }


def _parse_bte_profile(email: str, status_text: str, profile: dict) -> dict:
    """Parses authentic Behind the Email JSON profile into structured UI fields."""
    summary = profile.get("summary") or {}
    names = summary.get("names", [])
    usernames = summary.get("usernames", [])
    profile_pictures = summary.get("profilePictures", [])
    locations = summary.get("locations", [])
    links = summary.get("links", [])
    dates = summary.get("dates", [])

    primary_name = None
    if names and isinstance(names, list) and len(names) > 0:
        primary_name = names[0].get("value")
    if not primary_name and profile.get("linkedIn", {}).get("basic", {}).get("displayName"):
        primary_name = profile["linkedIn"]["basic"]["displayName"]
    if not primary_name and profile.get("google", {}).get("person", {}).get("personName"):
        primary_name = profile["google"]["person"]["personName"]
    if not primary_name and profile.get("github", {}).get("name"):
        primary_name = profile["github"]["name"]

    headline = None
    if profile.get("linkedIn", {}).get("basic", {}).get("headline"):
        headline = profile["linkedIn"]["basic"]["headline"]
    elif profile.get("github", {}).get("bio"):
        headline = profile["github"]["bio"]

    location = None
    if locations and isinstance(locations, list) and len(locations) > 0:
        location = locations[0].get("value")
    elif profile.get("linkedIn", {}).get("basic", {}).get("location"):
        location = profile["linkedIn"]["basic"]["location"]
    elif profile.get("github", {}).get("location"):
        location = profile["github"]["location"]

    pictures = []
    for pic in profile_pictures:
        if pic.get("value"):
            pictures.append({
                "url": pic["value"],
                "source": pic.get("formattedSource") or pic.get("source", "Profile")
            })

    active_providers = []
    for prov in ("linkedIn", "google", "github", "microsoft", "teams", "tiktok", "vsco", "duolingo", "chess"):
        if profile.get(prov):
            active_providers.append(prov)

    accounts_count = len(active_providers) or len(profile.get("registeredAccounts", {}).get("accounts", []))

    return {
        "status": status_text,
        "email": email,
        "full_name": primary_name,
        "headline": headline,
        "location": location,
        "accounts_count": accounts_count,
        "active_since": dates[0].get("value") if dates else None,
        "latest_activity": dates[-1].get("value") if dates else None,
        "profile_pictures": pictures,
        "summary": {
            "names": names,
            "usernames": usernames,
            "locations": locations,
            "links": links,
            "dates": dates
        },
        "providers": {
            "google": profile.get("google"),
            "github": profile.get("github"),
            "linkedIn": profile.get("linkedIn"),
            "microsoft": profile.get("microsoft"),
            "teams": profile.get("teams"),
            "tiktok": profile.get("tiktok"),
            "duolingo": profile.get("duolingo"),
            "dataBreach": profile.get("dataBreach"),
            "registeredAccounts": profile.get("registeredAccounts")
        }
    }
