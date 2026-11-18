"""
DNS Analyzer Service using Google Public DNS JSON API with fallback.
Performs real authoritative DNS queries for:
  - MX records (preference and host)
  - SPF records (TXT records beginning with v=spf1)
  - DMARC records (_dmarc.<domain>, TXT records beginning with v=DMARC1)
"""

import re
import logging
import requests
from typing import Dict, Any, List, Optional

logger = logging.getLogger("mailradar.dns")
GOOGLE_DNS_URL = "https://dns.google/resolve"
DEFAULT_TIMEOUT = 5.0

# DNS RCODE definitions per RFC 1035 / RFC 6895
DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED"
}


def _clean_txt_data(raw_data: str) -> str:
    """Strip quotes and leading/trailing whitespace from TXT record data."""
    if not raw_data:
        return ""
    data = raw_data.strip()
    if (data.startswith('"') and data.endswith('"')) or (data.startswith("'") and data.endswith("'")):
        data = data[1:-1].strip()
    data = data.replace('" "', '').replace('""', '')
    return data


def _dns_request(requester, params: dict):
    """Performs HTTP GET to Google Public DNS with automatic SSL recovery if network intercepts certificates."""
    try:
        return requester.get(
            GOOGLE_DNS_URL,
            params=params,
            headers={"Accept": "application/dns-json", "User-Agent": "MailRadar-DNS/1.0"},
            timeout=DEFAULT_TIMEOUT
        )
    except requests.exceptions.SSLError:
        import urllib3
        urllib3.disable_warnings()
        return requester.get(
            GOOGLE_DNS_URL,
            params=params,
            headers={"Accept": "application/dns-json", "User-Agent": "MailRadar-DNS/1.0"},
            timeout=DEFAULT_TIMEOUT,
            verify=False
        )


def check_mx(domain: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Performs real DNS MX lookup via Google Public DNS API.
    Returns:
        {
            "status": "Found" | "Not Found" | "Unknown" | <error>,
            "records": [{"priority": int, "host": str}, ...],
            "primary_mx": str | None,
            "error": str | None
        }
    """
    clean_domain = (domain or "").strip().lower()
    if not clean_domain:
        return {"status": "Not Found", "records": [], "primary_mx": None, "error": "Domain name is empty"}

    requester = session or requests
    try:
        resp = _dns_request(requester, {"name": clean_domain, "type": 15})
        if resp.status_code != 200:
            return {"status": "Unknown", "records": [], "primary_mx": None, "error": f"HTTP {resp.status_code}"}

        data = resp.json()
        status_code = data.get("Status", 0)

        if status_code == 0:
            records = []
            for ans in data.get("Answer", []):
                if ans.get("type") == 15:
                    parts = ans.get("data", "").strip().split(None, 1)
                    if len(parts) >= 2:
                        try:
                            records.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
                        except ValueError:
                            records.append({"priority": 999, "host": parts[1].rstrip(".")})
            if records:
                records.sort(key=lambda x: x["priority"])
                return {
                    "status": "Found",
                    "records": records,
                    "primary_mx": records[0]["host"],
                    "error": None
                }
            return {"status": "Not Found", "records": [], "primary_mx": None, "error": None}

        if status_code == 3:
            return {"status": "Not Found", "records": [], "primary_mx": None, "error": "Domain does not exist (NXDOMAIN)"}

        return {"status": f"DNS Error: {DNS_RCODES.get(status_code, str(status_code))}", "records": [], "primary_mx": None, "error": None}

    except requests.exceptions.Timeout:
        return {"status": "Unknown", "records": [], "primary_mx": None, "error": "DNS query timed out"}
    except Exception as e:
        return {"status": "Unknown", "records": [], "primary_mx": None, "error": str(e)}


def check_spf(domain: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Performs real DNS SPF lookup for TXT records starting with 'v=spf1'.
    """
    clean_domain = (domain or "").strip().lower()
    if not clean_domain:
        return {"status": "Not Found", "record": None, "policy": None, "total_txt_records": 0, "error": "Domain is empty"}

    requester = session or requests
    try:
        resp = _dns_request(requester, {"name": clean_domain, "type": 16})
        if resp.status_code != 200:
            return {"status": "Unknown", "record": None, "policy": None, "total_txt_records": 0, "error": f"HTTP {resp.status_code}"}

        data = resp.json()
        status_code = data.get("Status", 0)
        answers = data.get("Answer", [])
        txt_records = [ans for ans in answers if ans.get("type") == 16]
        total_txt = len(txt_records)

        if status_code == 0:
            spf_records = []
            for ans in txt_records:
                txt = _clean_txt_data(ans.get("data", ""))
                if txt.startswith("v=spf1"):
                    spf_records.append(txt)

            if spf_records:
                rec = spf_records[0]
                policy = rec
                if "~all" in rec:
                    policy = f"Softfail (~all) - {rec}"
                elif "-all" in rec:
                    policy = f"Hardfail (-all) - {rec}"
                elif "?all" in rec:
                    policy = f"Neutral (?all) - {rec}"
                elif "+all" in rec:
                    policy = f"Pass (+all) - {rec}"
                return {
                    "status": "Found",
                    "record": rec,
                    "policy": policy,
                    "total_txt_records": total_txt,
                    "all_spf_records": spf_records,
                    "error": None
                }
            return {
                "status": "Not Found",
                "record": None,
                "policy": None,
                "total_txt_records": total_txt,
                "error": "No SPF TXT record starting with v=spf1 found"
            }

        return {
            "status": "Not Found",
            "record": None,
            "policy": None,
            "total_txt_records": 0,
            "error": "Domain or records do not exist"
        }

    except requests.exceptions.Timeout:
        return {"status": "Unknown", "record": None, "policy": None, "total_txt_records": 0, "error": "DNS query timed out"}
    except Exception as e:
        return {"status": "Unknown", "record": None, "policy": None, "total_txt_records": 0, "error": str(e)}


def check_dmarc(domain: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Performs real DNS DMARC lookup on _dmarc.<domain> for TXT records starting with 'v=DMARC1'.
    """
    clean_domain = (domain or "").strip().lower()
    if not clean_domain:
        return {"status": "Not Found", "record": None, "policy": None, "host": None, "pct": None, "rua": None, "error": "Domain is empty"}

    dmarc_host = f"_dmarc.{clean_domain}"
    requester = session or requests
    try:
        resp = _dns_request(requester, {"name": dmarc_host, "type": 16})
        if resp.status_code != 200:
            return {"status": "Unknown", "record": None, "policy": None, "host": dmarc_host, "pct": None, "rua": None, "error": f"HTTP {resp.status_code}"}

        data = resp.json()
        status_code = data.get("Status", 0)

        if status_code == 0:
            dmarc_records = []
            for ans in data.get("Answer", []):
                if ans.get("type") == 16:
                    txt = _clean_txt_data(ans.get("data", ""))
                    if txt.startswith("v=DMARC1"):
                        dmarc_records.append(txt)

            if dmarc_records:
                rec = dmarc_records[0]
                policy = rec
                if "p=reject" in rec:
                    policy = f"Reject (p=reject) - {rec}"
                elif "p=quarantine" in rec:
                    policy = f"Quarantine (p=quarantine) - {rec}"
                elif "p=none" in rec:
                    policy = f"None (p=none) - {rec}"

                # Extract pct
                pct_match = re.search(r"pct=(\d+)", rec)
                pct = pct_match.group(1) if pct_match else None

                # Extract rua
                rua_match = re.search(r"rua=([^;\s]+)", rec)
                rua = rua_match.group(1) if rua_match else None

                return {
                    "status": "Found",
                    "record": rec,
                    "policy": policy,
                    "host": dmarc_host,
                    "pct": pct,
                    "rua": rua,
                    "error": None
                }
            return {
                "status": "Not Found",
                "record": None,
                "policy": None,
                "host": dmarc_host,
                "pct": None,
                "rua": None,
                "error": "No DMARC record"
            }

        if status_code == 3:
            return {
                "status": "Not Found",
                "record": None,
                "policy": None,
                "host": dmarc_host,
                "pct": None,
                "rua": None,
                "error": "Domain does not exist (NXDOMAIN)"
            }

        return {
            "status": "Not Found",
            "record": None,
            "policy": None,
            "host": dmarc_host,
            "pct": None,
            "rua": None,
            "error": f"DNS status {status_code}"
        }

    except requests.exceptions.Timeout:
        return {"status": "Unknown", "record": None, "policy": None, "host": dmarc_host, "pct": None, "rua": None, "error": "DNS query timed out"}
    except Exception as e:
        return {"status": "Unknown", "record": None, "policy": None, "host": dmarc_host, "pct": None, "rua": None, "error": str(e)}


def analyze_domain_dns(domain: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Combines MX, SPF, DMARC, and domain resolution for complete technical telemetry."""
    clean_domain = (domain or "").strip().lower()
    mx_res = check_mx(clean_domain, session)
    spf_res = check_spf(clean_domain, session)
    dmarc_res = check_dmarc(clean_domain, session)

    has_mx = (mx_res.get("status") == "Found" and len(mx_res.get("records", [])) > 0)
    service_status = "Operational"
    if mx_res.get("status") == "Unknown" or spf_res.get("status") == "Unknown" or dmarc_res.get("status") == "Unknown":
        service_status = "API Unavailable"

    return {
        "domain": clean_domain,
        "service_status": service_status,
        "mx": mx_res,
        "spf": spf_res,
        "dmarc": dmarc_res,
        "has_mx": has_mx,
        "domain_exists": {"status": "Found" if has_mx else mx_res.get("status", "Not Found")}
    }
