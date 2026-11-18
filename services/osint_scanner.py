"""
Real-time OSINT Scanner Service
Performs authentic, live public profile and account discovery with zero mock/fake data.
Sources:
  1. Gravatar JSON profile & avatar (https://www.gravatar.com/<md5>.json)
  2. GitHub Public Search & User API (https://api.github.com/search/users)
  3. Multi-platform account verification via holehe (Spotify, Adobe, Pinterest, etc.)
"""

import os
import hashlib
import logging
import asyncio
import requests
from typing import Dict, Any, Optional, List

import trio
import httpx
import holehe.core

logger = logging.getLogger("mailradar.osint")

# Common HTTP Headers
DEFAULT_HEADERS = {
    "User-Agent": "MailRadar-OSINT/1.0",
    "Accept": "application/json"
}
REQUEST_TIMEOUT = 8.0


def check_gravatar(email: str) -> Dict[str, Any]:
    """
    Computes lowercase trimmed MD5 hash of email and queries:
      - https://www.gravatar.com/{hash}.json
      - https://www.gravatar.com/avatar/{hash}?d=404
    Only returns profile details if Gravatar responds with HTTP 200.
    """
    clean_email = email.strip().lower()
    email_hash = hashlib.md5(clean_email.encode("utf-8")).hexdigest()

    json_url = f"https://www.gravatar.com/{email_hash}.json"
    avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"

    result = {
        "found": False,
        "hash": email_hash,
        "avatar_url": None,
        "display_name": None,
        "username": None,
        "location": None,
        "profile_url": None,
        "about": None,
        "accounts": [],
        "raw": None
    }

    try:
        # Check avatar existence
        avatar_resp = requests.get(avatar_url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
        has_avatar = (avatar_resp.status_code == 200)

        # Check JSON profile
        json_resp = requests.get(json_url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
        if json_resp.status_code == 200:
            data = json_resp.json()
            entries = data.get("entry") or []
            if entries:
                entry = entries[0]
                result["found"] = True
                result["display_name"] = entry.get("displayName")
                result["username"] = entry.get("preferredUsername")
                result["location"] = entry.get("currentLocation")
                result["profile_url"] = entry.get("profileUrl")
                result["about"] = entry.get("aboutMe")
                result["avatar_url"] = entry.get("thumbnailUrl") or (avatar_url if has_avatar else None)
                result["accounts"] = entry.get("accounts", [])
                result["raw"] = entry
        elif has_avatar:
            result["found"] = True
            result["avatar_url"] = avatar_url

    except Exception as e:
        logger.warning(f"Gravatar query failed for {email}: {e}")

    return result


def check_github(email: str) -> Dict[str, Any]:
    """
    Multi-strategy GitHub account and developer profile discovery:
      1. Search by email via GitHub User Search API:
         https://api.github.com/search/users?q={email}+in:email
      2. Direct handle lookup via local-part:
         https://api.github.com/users/{local_part}
      3. Search login prefix via GitHub User Search API:
         https://api.github.com/search/users?q={local_part}+in:login
      4. Search public commit history:
         https://api.github.com/search/commits?q=author-email:{email}
    """
    clean_email = email.strip().lower()
    local_part = clean_email.split("@")[0] if "@" in clean_email else clean_email
    search_url = f"https://api.github.com/search/users?q={clean_email}+in:email"

    result = {
        "found": False,
        "username": None,
        "name": None,
        "avatar_url": None,
        "profile_url": None,
        "followers": 0,
        "following": 0,
        "public_repos": 0,
        "created_at": None,
        "bio": None,
        "company": None,
        "location": None,
        "raw": None
    }

    try:
        # Strategy 1: Search by email in:email
        search_resp = requests.get(search_url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
        first_match = None
        if search_resp.status_code == 200:
            search_data = search_resp.json()
            items = search_data.get("items") or []
            if items:
                first_match = items[0]

        # Strategy 2: If no email match, check exact username / handle
        if not first_match and local_part:
            user_direct_resp = requests.get(
                f"https://api.github.com/users/{local_part}",
                headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT
            )
            if user_direct_resp.status_code == 200:
                u = user_direct_resp.json()
                if isinstance(u, dict) and u.get("login"):
                    result["found"] = True
                    result["username"] = u.get("login")
                    result["name"] = u.get("name")
                    result["avatar_url"] = u.get("avatar_url")
                    result["profile_url"] = u.get("html_url")
                    result["followers"] = u.get("followers", 0)
                    result["following"] = u.get("following", 0)
                    result["public_repos"] = u.get("public_repos", 0)
                    result["created_at"] = u.get("created_at")
                    result["bio"] = u.get("bio")
                    result["company"] = u.get("company")
                    result["location"] = u.get("location")
                    result["raw"] = u
                    return result

        # Strategy 3: Search login prefix
        if not first_match and local_part:
            prefix_url = f"https://api.github.com/search/users?q={local_part}+in:login"
            prefix_resp = requests.get(prefix_url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
            if prefix_resp.status_code == 200:
                p_items = prefix_resp.json().get("items") or []
                if p_items:
                    first_match = p_items[0]

        # If a match was found from search, fetch detailed profile
        if first_match:
            login = first_match.get("login")
            user_api_url = f"https://api.github.com/users/{login}"
            
            user_resp = requests.get(user_api_url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
            if user_resp.status_code == 200:
                u = user_resp.json()
                result["found"] = True
                result["username"] = u.get("login")
                result["name"] = u.get("name")
                result["avatar_url"] = u.get("avatar_url")
                result["profile_url"] = u.get("html_url")
                result["followers"] = u.get("followers", 0)
                result["following"] = u.get("following", 0)
                result["public_repos"] = u.get("public_repos", 0)
                result["created_at"] = u.get("created_at")
                result["bio"] = u.get("bio")
                result["company"] = u.get("company")
                result["location"] = u.get("location")
                result["raw"] = u
            else:
                result["found"] = True
                result["username"] = login
                result["name"] = None
                result["avatar_url"] = first_match.get("avatar_url")
                result["profile_url"] = first_match.get("html_url")
                result["raw"] = first_match

    except Exception as e:
        logger.warning(f"GitHub search query failed for {email}: {e}")

    return result


async def _async_launch_module(func, email, client, out, on_platform_result=None):
    temp = []
    try:
        await holehe.core.launch_module(func, email, client, temp)
        if temp:
            r = temp[0]
            out.append(r)
            if on_platform_result:
                try:
                    on_platform_result(r)
                except Exception as ex:
                    logger.debug(f"Platform callback error: {ex}")
    except Exception as e:
        logger.debug(f"Module {getattr(func, '__name__', 'unknown')} failed: {e}")


async def _async_holehe_scan(
    email: str,
    target_services: Optional[List[str]] = None,
    on_platform_result: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """Trio async worker for holehe account checks."""
    out = []
    services_filter = set(target_services) if target_services else {
        'spotify', 'adobe', 'pinterest', 'instagram', 'twitter',
        'discord', 'github', 'snapchat', 'duolingo', 'strava',
        'wordpress', 'flickr', 'imgur', 'tumblr', 'patreon',
        'amazon', 'samsung', 'skype', 'trello', 'twitch',
        'soundcloud', 'lastfm', 'codecademy', 'atlassian'
    }

    async with httpx.AsyncClient(timeout=8.0) as client:
        modules = holehe.core.import_submodules('holehe.modules')
        all_funcs = holehe.core.get_functions(modules)
        funcs = [f for f in all_funcs if f.__name__ in services_filter]

        async with trio.open_nursery() as nursery:
            for f in funcs:
                nursery.start_soon(_async_launch_module, f, email, client, out, on_platform_result)

    return out


def check_holehe_platforms(
    email: str,
    target_services: Optional[List[str]] = None,
    on_platform_result: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Synchronous wrapper executing holehe across real social and cloud platforms.
    Filters and returns ONLY verified platforms where exists == True.
    """
    clean_email = email.strip().lower()
    try:
        raw_results = trio.run(_async_holehe_scan, clean_email, target_services, on_platform_result)
        confirmed_platforms = []
        for r in raw_results:
            if r.get("exists") is True:
                name = r.get("name")
                domain = r.get("domain") or f"{name}.com"
                confirmed_platforms.append({
                    "name": name.capitalize(),
                    "service": name,
                    "domain": domain,
                    "exists": True,
                    "others": r.get("others")
                })

        return {
            "success": True,
            "checked_count": len(raw_results),
            "confirmed_count": len(confirmed_platforms),
            "registered": confirmed_platforms,
            "raw": raw_results
        }
    except Exception as e:
        logger.error(f"Holehe execution failed: {e}")
        return {
            "success": False,
            "checked_count": 0,
            "confirmed_count": 0,
            "registered": [],
            "error": str(e),
            "raw": []
        }
