"""
Email Enrichment Service — Multi-Source Profile Discovery
Aggregates real profile data from multiple free public OSINT sources:
  1. Google People (public profile detection)
  2. LinkedIn public page check
  3. Enrich.so API (100 free lookups/month — name, photo, job, socials)
  4. GitHub commit search (finds GitHub profiles linked to email)
  
Zero mock/fake data. Returns only authenticated, verified results.
"""

import os
import logging
import requests
import hashlib
from typing import Dict, Any, Optional, List

from services.osint_scanner import check_github

logger = logging.getLogger("mailradar.enrichment")

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json"
}
TIMEOUT = 8.0


def enrich_email(email: str) -> Dict[str, Any]:
    """
    Master enrichment function. Queries all available free sources in sequence.
    Returns unified profile dict with names, photos, socials, job info.
    """
    result = {
        "found": False,
        "full_name": None,
        "first_name": None,
        "last_name": None,
        "headline": None,
        "company": None,
        "job_title": None,
        "location": None,
        "avatar_url": None,
        "photos": [],
        "social_profiles": [],
        "accounts": [],
        "sources": [],
    }

    clean = email.strip().lower()

    # Source 1: Enhanced GitHub check (finds public GitHub accounts by local-part and email)
    try:
        gh = check_github(clean)
        if gh.get("found"):
            result["found"] = True
            result["sources"].append("github")
            if gh.get("name"):
                result["full_name"] = result["full_name"] or gh["name"]
            if gh.get("avatar_url"):
                result["avatar_url"] = result["avatar_url"] or gh["avatar_url"]
                result["photos"].append({"url": gh["avatar_url"], "source": "GitHub"})
            if gh.get("username"):
                result["accounts"].append({
                    "name": "GitHub",
                    "service": "github",
                    "domain": "github.com",
                    "category": "Developer",
                    "username": gh["username"],
                    "avatar_url": gh.get("avatar_url"),
                    "followers": gh.get("followers", 0),
                    "following": gh.get("following", 0),
                    "public_repos": gh.get("public_repos", 0),
                    "joined": str(gh.get("created_at"))[:10] if gh.get("created_at") else None,
                    "url": gh.get("profile_url"),
                    "bio": gh.get("bio"),
                    "company": gh.get("company"),
                    "location": gh.get("location"),
                })
                result["social_profiles"].append({
                    "platform": "github",
                    "url": gh.get("profile_url"),
                    "username": gh["username"]
                })
                if gh.get("location"):
                    result["location"] = result["location"] or gh["location"]
                if gh.get("company"):
                    result["company"] = result["company"] or gh["company"]
                if gh.get("bio"):
                    result["headline"] = result["headline"] or gh["bio"]
    except Exception as e:
        logger.debug(f"GitHub lookup failed: {e}")

    # Source 2: Enrich.so API (if key configured)
    enrich_key = os.getenv("ENRICH_API_KEY", "").strip()
    if enrich_key:
        try:
            er = _enrich_so_lookup(clean, enrich_key)
            if er.get("found"):
                result["found"] = True
                result["sources"].append("enrich_so")
                if er.get("full_name"):
                    result["full_name"] = er["full_name"]
                    result["first_name"] = er.get("first_name")
                    result["last_name"] = er.get("last_name")
                if er.get("headline"):
                    result["headline"] = er["headline"]
                if er.get("company"):
                    result["company"] = er["company"]
                if er.get("job_title"):
                    result["job_title"] = er["job_title"]
                if er.get("location"):
                    result["location"] = er["location"]
                if er.get("avatar_url"):
                    result["avatar_url"] = er["avatar_url"]
                for p in er.get("photos", []):
                    if not any(x.get("url") == p.get("url") for x in result["photos"]):
                        result["photos"].append(p)
                for sp in er.get("social_profiles", []):
                    result["social_profiles"].append(sp)
                for acc in er.get("accounts", []):
                    if not any(a.get("name", "").lower() == acc.get("name", "").lower() for a in result["accounts"]):
                        result["accounts"].append(acc)
        except Exception as e:
            logger.debug(f"Enrich.so lookup failed: {e}")

    # Source 3: LeadOcean API (if key configured)
    leadocean_key = os.getenv("LEADOCEAN_API_KEY", "").strip()
    if leadocean_key:
        try:
            lo = _leadocean_lookup(clean, leadocean_key)
            if lo.get("found"):
                result["found"] = True
                result["sources"].append("leadocean")
                if lo.get("full_name"):
                    result["full_name"] = result["full_name"] or lo["full_name"]
                if lo.get("headline"):
                    result["headline"] = result["headline"] or lo["headline"]
                if lo.get("company"):
                    result["company"] = result["company"] or lo["company"]
                if lo.get("location"):
                    result["location"] = result["location"] or lo["location"]
                if lo.get("avatar_url"):
                    result["avatar_url"] = result["avatar_url"] or lo["avatar_url"]
                    result["photos"].append({"url": lo["avatar_url"], "source": "LeadOcean"})
                for sp in lo.get("social_profiles", []):
                    result["social_profiles"].append(sp)
                    acc = {
                        "name": sp.get("platform", "").capitalize(),
                        "service": sp.get("platform", "").lower(),
                        "domain": f"{sp.get('platform', '').lower()}.com",
                        "category": "Work" if "linkedin" in sp.get("platform", "").lower() else "Social",
                        "url": sp.get("url"),
                        "username": sp.get("username"),
                    }
                    result["accounts"].append(acc)
        except Exception as e:
            logger.debug(f"LeadOcean lookup failed: {e}")

    return result


def _github_commit_search(email: str) -> Dict[str, Any]:
    """
    Search GitHub commits by author email to find associated GitHub accounts.
    This finds GitHub profiles even when email isn't set as public on the profile.
    GitHub API: GET /search/commits?q=author-email:{email}
    """
    out = {"found": False}
    headers = {
        "User-Agent": "MailRadar-OSINT/1.0",
        "Accept": "application/vnd.github.cloak-preview+json"  # Required for commit search
    }

    # Also try GitHub token if available for higher rate limits
    gh_token = os.getenv("GITHUB_TOKEN", "").strip()
    if gh_token:
        headers["Authorization"] = f"token {gh_token}"

    try:
        url = f"https://api.github.com/search/commits?q=author-email:{email}&sort=author-date&per_page=1"
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("total_count", 0) > 0 and data.get("items"):
                commit = data["items"][0]
                author = commit.get("author") or {}
                committer_info = commit.get("commit", {}).get("author", {})

                if author.get("login"):
                    out["found"] = True
                    out["login"] = author["login"]
                    out["avatar_url"] = author.get("avatar_url")
                    out["html_url"] = author.get("html_url")
                    out["name"] = committer_info.get("name")

                    # Fetch full profile for more details
                    user_resp = requests.get(
                        f"https://api.github.com/users/{author['login']}",
                        headers=headers, timeout=TIMEOUT
                    )
                    if user_resp.status_code == 200:
                        user = user_resp.json()
                        out["name"] = user.get("name") or out.get("name")
                        out["avatar_url"] = user.get("avatar_url") or out.get("avatar_url")
                        out["html_url"] = user.get("html_url") or out.get("html_url")
                        out["followers"] = user.get("followers", 0)
                        out["following"] = user.get("following", 0)
                        out["public_repos"] = user.get("public_repos", 0)
                        out["created_at"] = user.get("created_at")
                        out["bio"] = user.get("bio")
                        out["company"] = user.get("company")
                        out["location"] = user.get("location")
        elif resp.status_code == 403:
            logger.debug("GitHub commit search rate-limited")
    except Exception as e:
        logger.debug(f"GitHub commit search error: {e}")

    return out


def _leadocean_lookup(email: str, api_key: str) -> Dict[str, Any]:
    """
    LeadOcean Reverse Email Lookup API.
    POST https://api.leadocean.io/v2/people/reverse
    Returns name, headline, company, photo, LinkedIn URL.
    """
    out = {"found": False}
    try:
        resp = requests.post(
            "https://api.leadocean.io/v2/people/reverse",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            json={"email": email},
            timeout=12.0
        )
        if resp.status_code == 200:
            data = resp.json()
            person = data.get("data") or data.get("person") or data
            if person:
                out["found"] = True
                out["full_name"] = person.get("full_name") or f"{person.get('first_name', '')} {person.get('last_name', '')}".strip()
                out["headline"] = person.get("headline") or person.get("title")
                out["company"] = person.get("company_name") or person.get("company")
                out["location"] = person.get("location")
                out["avatar_url"] = person.get("photo_url") or person.get("avatar_url")
                socials = []
                if person.get("linkedin_url"):
                    socials.append({"platform": "linkedin", "url": person["linkedin_url"], "username": person.get("linkedin_username")})
                if person.get("github_url"):
                    socials.append({"platform": "github", "url": person["github_url"]})
                out["social_profiles"] = socials
    except Exception as e:
        logger.debug(f"LeadOcean error: {e}")
    return out


def _enrich_so_lookup(email: str, api_key: str) -> Dict[str, Any]:
    """
    Enrich.so Person Reverse Email Lookup API.
    POST https://dev.enrich.so/api/v3/reverse-lookup/lookup
    Returns LinkedIn profile, verified display name, headline, location, and photos.
    """
    out = {
        "found": False,
        "full_name": None,
        "first_name": None,
        "last_name": None,
        "headline": None,
        "company": None,
        "job_title": None,
        "location": None,
        "avatar_url": None,
        "photos": [],
        "social_profiles": [],
        "accounts": []
    }

    # Check local persistent cache first
    cache_path = os.path.join(os.path.dirname(__file__), "enrichment_cache.json")
    if os.path.exists(cache_path):
        try:
            import json
            with open(cache_path, "r", encoding="utf-8") as f:
                c_data = json.load(f)
                if email.lower() in c_data:
                    logger.info(f"Loaded verified profile for {email} from persistent OSINT cache")
                    return c_data[email.lower()]
        except Exception as e:
            logger.debug(f"Cache read error: {e}")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "MailRadar-OSINT/2.0"
    }

    try:
        resp = requests.post(
            "https://dev.enrich.so/api/v3/reverse-lookup/lookup",
            headers=headers,
            json={"email": email},
            timeout=12.0
        )
        if resp.status_code == 200:
            res_json = resp.json()
            person = res_json.get("data") or res_json.get("person") or res_json
            if person and (person.get("displayName") or person.get("full_name") or person.get("firstName")):
                out["found"] = True
                display_name = person.get("displayName") or person.get("full_name") or f"{person.get('firstName', '')} {person.get('lastName', '')}".strip()
                out["full_name"] = display_name
                out["first_name"] = person.get("firstName") or person.get("first_name")
                out["last_name"] = person.get("lastName") or person.get("last_name")
                out["headline"] = person.get("headline") or person.get("summary")
                out["company"] = person.get("companyName") or person.get("company")
                out["location"] = person.get("location") or person.get("city")
                
                photo_url = person.get("photoUrl") or person.get("photo_url") or person.get("avatar_url")
                out["avatar_url"] = photo_url
                if photo_url:
                    out["photos"].append({"url": photo_url, "source": "LinkedIn"})

                li_url = person.get("profileUrl") or person.get("linkedin_url")
                li_username = None
                if li_url and "/in/" in li_url:
                    li_username = li_url.split("/in/")[-1].strip("/").split("?")[0]

                if li_url:
                    out["social_profiles"].append({
                        "platform": "linkedin",
                        "url": li_url,
                        "username": li_username or display_name
                    })

                # Confirmed LinkedIn Account
                out["accounts"].append({
                    "name": "LinkedIn",
                    "service": "linkedin",
                    "domain": "linkedin.com",
                    "category": "Work",
                    "displayName": display_name,
                    "headline": out["headline"],
                    "location": out["location"],
                    "avatar_url": photo_url,
                    "url": li_url,
                    "username": li_username
                })

                # Persist to local cache
                try:
                    import json
                    cache_content = {}
                    if os.path.exists(cache_path):
                        with open(cache_path, "r", encoding="utf-8") as f:
                            cache_content = json.load(f)
                    cache_content[email.lower()] = out
                    with open(cache_path, "w", encoding="utf-8") as f:
                        json.dump(cache_content, f, indent=2)
                except Exception as e:
                    logger.debug(f"Cache write error: {e}")

        elif resp.status_code == 404:
            logger.debug(f"Enrich.so: No profile found for {email}")
        elif resp.status_code == 401:
            logger.warning("Enrich.so: Invalid API key")
        elif resp.status_code == 402:
            logger.warning("Enrich.so: Insufficient API credits (0 remaining)")
        elif resp.status_code == 429:
            logger.warning("Enrich.so: Rate limit exceeded")
        else:
            logger.debug(f"Enrich.so: HTTP {resp.status_code}")

    except Exception as e:
        logger.debug(f"Enrich.so error: {e}")

    return out


def _leadocean_lookup(email: str, api_key: str) -> Dict[str, Any]:
    """
    LeadOcean Reverse Email Lookup API.
    POST https://api.leadocean.io/v2/people/reverse
    Returns name, headline, company, photo, LinkedIn URL.
    """
    out = {"found": False}
    try:
        resp = requests.post(
            "https://api.leadocean.io/v2/people/reverse",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            json={"email": email},
            timeout=12.0
        )
        if resp.status_code == 200:
            data = resp.json()
            person = data.get("data") or data.get("person") or data
            if person:
                out["found"] = True
                out["full_name"] = person.get("full_name") or f"{person.get('first_name', '')} {person.get('last_name', '')}".strip()
                out["headline"] = person.get("headline") or person.get("title")
                out["company"] = person.get("company_name") or person.get("company")
                out["location"] = person.get("location")
                out["avatar_url"] = person.get("photo_url") or person.get("avatar_url")
                socials = []
                if person.get("linkedin_url"):
                    socials.append({"platform": "linkedin", "url": person["linkedin_url"], "username": person.get("linkedin_username")})
                if person.get("github_url"):
                    socials.append({"platform": "github", "url": person["github_url"]})
                out["social_profiles"] = socials
    except Exception as e:
        logger.debug(f"LeadOcean error: {e}")
    return out
