"""
MailRadar Automated Test Suite
Covers:
  - Valid and invalid email syntax
  - check_mx: MX records found, missing, timeout, priority parsing
  - check_spf: SPF records found vs missing TXT records (distinct handling), timeout
  - check_dmarc: DMARC records found, missing, NXDOMAIN, timeout
  - check_email_reputation (Abstract Email Reputation API):
      - Valid email & successful response parsing (deliverability, quality, risk, sender, breaches)
      - Invalid email input
      - API key missing
      - Invalid API key (HTTP 401/403)
      - API quota exceeded (HTTP 429 & error JSON)
      - Network timeout & connection errors
  - Partial API failure (Google DNS succeeds while Abstract fails)
  - Flask endpoints (/api/health, /api/analyze)
  - Verification of structured JSON keys: domain, mx_status, mx_records, spf_status, spf_record, dmarc_status, dmarc_record, abstract_api, reputation
"""

import unittest
from unittest.mock import patch, MagicMock
import requests

from services.email_validator import (
    validate_email_syntax,
    check_email_reputation,
    query_abstract_api
)
from services.dns_analyzer import (
    check_mx,
    check_spf,
    check_dmarc,
    analyze_domain_dns
)
from services.reputation import query_emailrep
from services.intelbase import query_intelbase_email, get_intelbase_egress_ip
from services.hibp_analyzer import check_hibp_breaches
from services.behind_the_email import query_behind_the_email, check_bte_api_health
from services.osint_scanner import check_gravatar, check_github
from app import app


class TestEmailValidator(unittest.TestCase):

    def test_valid_emails(self):
        """Test valid email addresses per RFC 5322."""
        valid_cases = [
            "security@google.com",
            "first.last@domain.org",
            "support+tag@sub.example.co.uk",
            "analyst_123@sec-corp.io",
            "a@b.com"
        ]
        for email in valid_cases:
            res = validate_email_syntax(email)
            self.assertTrue(res["is_valid"], f"Failed for {email}")
            self.assertEqual(res["status"], "Valid")
            self.assertIsNotNone(res["domain"])

    def test_invalid_emails(self):
        """Test malformed and invalid email addresses."""
        invalid_cases = [
            "",                        # Empty
            "no-at-sign.com",          # Missing @
            "@no-local.com",           # Empty local
            "no-domain@",              # Empty domain
            "double..dot@domain.com",  # Consecutive dots
            ".leadingdot@domain.com",  # Leading dot
            "trailingdot.@domain.com", # Trailing dot in local part
            "user@domain..com",        # Double dot in domain
            "user@nodot",              # Missing TLD
            "user@-hyphen.com",        # Leading hyphen in domain
            "a" * 65 + "@domain.com",  # Local part > 64 chars
            "user@" + "a" * 256 + ".com" # Domain part > 255 chars
        ]
        for email in invalid_cases:
            res = validate_email_syntax(email)
            self.assertFalse(res["is_valid"], f"Should be invalid: {email}")
            self.assertEqual(res["status"], "Invalid")
            self.assertIsNotNone(res["error"])


class TestDnsAnalyzerFunctions(unittest.TestCase):

    @patch("services.dns_analyzer.requests.get")
    def test_check_mx_found(self, mock_get):
        """Test check_mx parses DNS type 15 response and extracts priority and host."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0,
            "Answer": [
                {"type": 15, "data": "20 alt1.aspmx.l.google.com."},
                {"type": 15, "data": "10 aspmx.l.google.com."}
            ]
        }
        mock_get.return_value = mock_resp

        res = check_mx("google.com")
        self.assertEqual(res["status"], "Found")
        self.assertEqual(len(res["records"]), 2)
        # Verify sorting by priority
        self.assertEqual(res["records"][0]["priority"], 10)
        self.assertEqual(res["records"][0]["host"], "aspmx.l.google.com")
        self.assertEqual(res["records"][1]["priority"], 20)
        self.assertEqual(res["records"][1]["host"], "alt1.aspmx.l.google.com")
        self.assertEqual(res["primary_mx"], "aspmx.l.google.com")

    @patch("services.dns_analyzer.requests.get")
    def test_check_mx_missing(self, mock_get):
        """Test check_mx returns Not Found when domain has Status 0 but no MX records."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0,
            "Answer": []
        }
        mock_get.return_value = mock_resp

        res = check_mx("neverssl.com")
        self.assertEqual(res["status"], "Not Found")
        self.assertEqual(res["records"], [])
        self.assertIsNone(res["primary_mx"])

    @patch("services.dns_analyzer.requests.get")
    def test_check_mx_timeout(self, mock_get):
        """Test check_mx returns Unknown on network timeout."""
        mock_get.side_effect = requests.exceptions.Timeout("Timed out")
        res = check_mx("timeout.com")
        self.assertEqual(res["status"], "Unknown")
        self.assertEqual(res["records"], [])

    @patch("services.dns_analyzer.requests.get")
    def test_check_spf_found(self, mock_get):
        """Test check_spf queries type 16 and extracts v=spf1 record."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0,
            "Answer": [
                {"type": 16, "data": '"google-site-verification=abc"'},
                {"type": 16, "data": '"v=spf1 include:_spf.google.com ~all"'}
            ]
        }
        mock_get.return_value = mock_resp

        res = check_spf("google.com")
        self.assertEqual(res["status"], "Found")
        self.assertEqual(res["record"], "v=spf1 include:_spf.google.com ~all")
        self.assertIn("Softfail", res["policy"])
        self.assertEqual(res["total_txt_records"], 2)

    @patch("services.dns_analyzer.requests.get")
    def test_check_spf_not_confused_with_other_txt(self, mock_get):
        """Test requirement: do not treat other TXT records as SPF."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0,
            "Answer": [
                {"type": 16, "data": '"google-site-verification=xyz987"'},
                {"type": 16, "data": '"MS=ms123456"'}
            ]
        }
        mock_get.return_value = mock_resp

        res = check_spf("example.com")
        self.assertEqual(res["status"], "Not Found")
        self.assertIsNone(res["record"])
        self.assertEqual(res["total_txt_records"], 2)

    @patch("services.dns_analyzer.requests.get")
    def test_check_spf_no_records(self, mock_get):
        """Test check_spf when domain has no TXT records at all."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0,
            "Answer": []
        }
        mock_get.return_value = mock_resp

        res = check_spf("notxt.com")
        self.assertEqual(res["status"], "Not Found")
        self.assertIsNone(res["record"])
        self.assertEqual(res["total_txt_records"], 0)

    @patch("services.dns_analyzer.requests.get")
    def test_check_dmarc_found(self, mock_get):
        """Test check_dmarc queries _dmarc.<domain> type 16 and extracts v=DMARC1."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0,
            "Answer": [
                {"type": 16, "data": '"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@google.com"'}
            ]
        }
        mock_get.return_value = mock_resp

        res = check_dmarc("google.com")
        self.assertEqual(res["status"], "Found")
        self.assertEqual(res["record"], "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@google.com")
        self.assertIn("Reject", res["policy"])
        self.assertEqual(res["pct"], "100")
        self.assertEqual(res["rua"], "mailto:dmarc@google.com")

    @patch("services.dns_analyzer.requests.get")
    def test_check_dmarc_missing(self, mock_get):
        """Test check_dmarc returns Not Found when no DMARC record exists (NXDOMAIN or empty)."""
        # Case A: Status 3 (NXDOMAIN on _dmarc)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 3,
            "Answer": []
        }
        mock_get.return_value = mock_resp

        res = check_dmarc("nodmarc.com")
        self.assertEqual(res["status"], "Not Found")
        self.assertIsNone(res["record"])

        # Case B: Status 0 but empty Answer
        mock_resp.json.return_value = {
            "Status": 0,
            "Answer": []
        }
        res2 = check_dmarc("nodmarc2.com")
        self.assertEqual(res2["status"], "Not Found")
        self.assertIsNone(res2["record"])


class TestAbstractEmailReputation(unittest.TestCase):

    @patch("services.email_validator.requests.get")
    def test_reputation_successful_response(self, mock_get):
        """Test successful Abstract Email Reputation response parsing."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "email_address": "security@google.com",
            "suggested_correction": None,
            "email_deliverability": {
                "status": "deliverable",
                "status_detail": "valid_email",
                "is_format_valid": True,
                "is_smtp_valid": True,
                "is_mx_valid": True,
                "mx_records": ["smtp.google.com"]
            },
            "email_quality": {
                "score": 0.85,
                "is_free_email": False,
                "is_username_suspicious": False,
                "is_disposable": False,
                "is_catchall": False,
                "is_subaddress": False,
                "is_role": True,
                "is_dmarc_enforced": True,
                "is_spf_strict": True,
                "minimum_age": 5000
            },
            "email_sender": {
                "first_name": "Security",
                "last_name": None,
                "email_provider_name": "Google",
                "organization_name": "Google LLC",
                "organization_type": "commercial"
            },
            "email_domain": {
                "domain": "google.com",
                "domain_age": 10650,
                "is_live_site": True,
                "registrar": "MarkMonitor, Inc.",
                "is_risky_tld": False
            },
            "email_risk": {
                "address_risk_status": "low",
                "domain_risk_status": "low"
            },
            "email_breaches": {
                "total_breaches": 5,
                "date_first_breached": "2015-01-01",
                "date_last_breached": "2024-01-01",
                "breached_domains": [{"domain": "breached.site", "breach_date": "2024-01-01"}]
            }
        }
        mock_get.return_value = mock_resp

        res = check_email_reputation("security@google.com", api_key="test_mock_key")
        self.assertEqual(res["status"], "Available")
        self.assertTrue(res["is_configured"])
        self.assertIsNotNone(res["data"])

        d = res["data"]
        self.assertEqual(d["deliverability"], "DELIVERABLE")
        self.assertEqual(d["quality_score"], 0.85)
        self.assertEqual(d["email_deliverability"]["status_detail"], "valid_email")
        self.assertTrue(d["email_deliverability"]["is_smtp_valid"])
        self.assertFalse(d["email_quality"]["is_free_email"])
        self.assertFalse(d["email_quality"]["is_disposable"])
        self.assertEqual(d["email_risk"]["address_risk_status"], "low")
        self.assertEqual(d["email_breaches"]["total_breaches"], 5)
        self.assertEqual(d["email_sender"]["organization_name"], "Google LLC")
        self.assertEqual(d["email_domain"]["domain_age"], 10650)

    def test_reputation_invalid_email_input(self):
        """Test check_email_reputation rejects invalid email without network call."""
        res = check_email_reputation("not-an-email", api_key="mock_key")
        self.assertEqual(res["status"], "Invalid Email")
        self.assertIn("Syntax invalid", res["message"])
        self.assertIsNone(res["data"])

    def test_reputation_missing_api_key(self):
        """Test check_email_reputation handles missing API key cleanly."""
        res = check_email_reputation("user@example.com", api_key="")
        self.assertEqual(res["status"], "Not Configured")
        self.assertFalse(res["is_configured"])
        self.assertIsNone(res["data"])

    @patch("services.email_validator.requests.get")
    def test_reputation_invalid_api_key_401(self, mock_get):
        """Test check_email_reputation handles HTTP 401 Unauthorized."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        res = check_email_reputation("user@example.com", api_key="bad_key")
        self.assertEqual(res["status"], "Invalid API Key")
        self.assertIn("Invalid or expired", res["message"])
        self.assertIsNone(res["data"])

    @patch("services.email_validator.requests.get")
    def test_reputation_quota_exceeded_429(self, mock_get):
        """Test check_email_reputation handles HTTP 429 Too Many Requests."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        res = check_email_reputation("user@example.com", api_key="limited_key")
        self.assertEqual(res["status"], "Quota Exceeded")
        self.assertIn("quota exceeded", res["message"].lower())
        self.assertIsNone(res["data"])

    @patch("services.email_validator.requests.get")
    def test_reputation_quota_in_json_body(self, mock_get):
        """Test check_email_reputation handles quota error returned inside JSON payload."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "error": {
                "message": "Monthly API quota exceeded for plan",
                "code": "quota_exceeded"
            }
        }
        mock_get.return_value = mock_resp

        res = check_email_reputation("user@example.com", api_key="limited_key")
        self.assertEqual(res["status"], "Quota Exceeded")
        self.assertIn("quota", res["message"].lower())
        self.assertIsNone(res["data"])

    @patch("services.email_validator.requests.get")
    def test_reputation_timeout(self, mock_get):
        """Test check_email_reputation handles network timeout."""
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
        res = check_email_reputation("user@example.com", api_key="mock_key")
        self.assertEqual(res["status"], "API Unavailable")
        self.assertIn("timed out", res["message"])
        self.assertIsNone(res["data"])

    @patch("services.email_validator.requests.get")
    def test_reputation_network_error(self, mock_get):
        """Test check_email_reputation handles network connection failure."""
        mock_get.side_effect = requests.exceptions.ConnectionError("DNS failure")
        res = check_email_reputation("user@example.com", api_key="mock_key")
        self.assertEqual(res["status"], "API Unavailable")
        self.assertIn("Network failure", res["message"])
        self.assertIsNone(res["data"])


class TestApiErrorsAndTimeouts(unittest.TestCase):

    @patch("services.dns_analyzer.requests.get")
    def test_dns_timeout(self, mock_get):
        """Test handling of Google Public DNS timeouts in full domain analysis."""
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
        res = analyze_domain_dns("timeout-domain.com")
        self.assertEqual(res["service_status"], "API Unavailable")
        self.assertEqual(res["mx"]["status"], "Unknown")
        self.assertEqual(res["spf"]["status"], "Unknown")
        self.assertEqual(res["dmarc"]["status"], "Unknown")

    @patch("services.reputation.requests.get")
    def test_emailrep_unconfigured_and_invalid_key(self, mock_get):
        """Test EmailRep service when unconfigured and when key is invalid."""
        res_no_key = query_emailrep("user@example.com", api_key="")
        self.assertEqual(res_no_key["status"], "Not Configured")
        self.assertEqual(res_no_key["message"], "Email reputation: Not configured.")
        mock_get.assert_not_called()

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        res_bad_key = query_emailrep("user@example.com", api_key="bad_emailrep_key")
        self.assertEqual(res_bad_key["status"], "Invalid API Key")

    @patch("app.check_email_reputation")
    @patch("services.dns_analyzer.requests.get")
    def test_partial_api_failure(self, mock_dns, mock_abstract):
        """
        Test partial API failure:
        Google DNS succeeds while Abstract API fails with a 429 quota error.
        Application must still return accurate DNS results and clearly label Abstract API.
        """
        def dns_side_effect(url, params=None, headers=None, timeout=None):
            resp = MagicMock()
            resp.status_code = 200
            p = params or {}
            t = p.get("type")
            name = p.get("name", "")
            if t == "A":
                resp.json.return_value = {"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]}
            elif t == 15 or t == "15" or t == "MX":
                resp.json.return_value = {"Status": 0, "Answer": [{"type": 15, "data": "10 mail.company.com."}]}
            elif t == 16 or t == "16" or t == "TXT":
                if name.startswith("_dmarc."):
                    resp.json.return_value = {"Status": 0, "Answer": [{"type": 16, "data": '"v=DMARC1; p=reject"'}]}
                else:
                    resp.json.return_value = {"Status": 0, "Answer": [{"type": 16, "data": '"v=spf1 -all"'}]}
            return resp

        mock_dns.side_effect = dns_side_effect

        mock_abstract.return_value = {
            "status": "Quota Exceeded",
            "is_configured": True,
            "message": "Abstract API quota exceeded or rate limit reached.",
            "data": None
        }

        client = app.test_client()
        response = client.post("/api/analyze", json={"email": "employee@company.com"})
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertTrue(data["success"])
        # Top-level structured JSON keys
        self.assertEqual(data["domain"], "company.com")
        self.assertEqual(data["mx_status"], "Found")
        self.assertEqual(data["spf_status"], "Found")
        self.assertEqual(data["dmarc_status"], "Found")
        # Abstract must reflect Quota Exceeded without breaking application
        self.assertEqual(data["abstract_api"]["status"], "Quota Exceeded")
        self.assertEqual(data["reputation"]["status"], "Quota Exceeded")


class TestFlaskEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_health_endpoint(self):
        """Test GET /api/health."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "MailRadar")

    def test_analyze_empty_request(self):
        """Test POST /api/analyze with missing payload."""
        res = self.client.post("/api/analyze", json={})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])

    def test_analyze_invalid_email_syntax(self):
        """Test POST /api/analyze immediately halts and returns 400 on invalid format or missing TLD."""
        for invalid in ["not-an-email", "usmjsjcejd@123", "user@domain..com", "@nodomain.com"]:
            res = self.client.post("/api/analyze", json={"email": invalid})
            self.assertEqual(res.status_code, 400, f"Expected 400 for {invalid}")
            data = res.get_json()
            self.assertFalse(data["success"])
            self.assertIn("Invalid email format", data["error"])

    @patch("app.check_email_reputation")
    @patch("services.dns_analyzer.requests.get")
    def test_analyze_valid_email_full_flow(self, mock_dns, mock_rep):
        """
        Test POST /api/analyze with valid email.
        Verifies all required keys and Abstract Reputation integration.
        """
        def dns_side_effect(url, params=None, headers=None, timeout=None):
            resp = MagicMock()
            resp.status_code = 200
            p = params or {}
            t = p.get("type")
            name = p.get("name", "")
            if t == "A":
                resp.json.return_value = {"Status": 0, "Answer": [{"type": 1, "data": "142.250.190.46"}]}
            elif t == 15 or t == "15" or t == "MX":
                resp.json.return_value = {"Status": 0, "Answer": [{"type": 15, "data": "10 smtp.google.com"}]}
            elif t == 16 or t == "16" or t == "TXT":
                if name.startswith("_dmarc."):
                    resp.json.return_value = {"Status": 0, "Answer": [{"type": 16, "data": '"v=DMARC1; p=reject; pct=100"'}]}
                else:
                    resp.json.return_value = {"Status": 0, "Answer": [{"type": 16, "data": '"v=spf1 include:_spf.google.com ~all"'}]}
            return resp

        mock_dns.side_effect = dns_side_effect

        mock_rep.return_value = {
            "status": "Available",
            "is_configured": True,
            "message": "Abstract Email Reputation API responded successfully",
            "data": {
                "email_address": "security@google.com",
                "email_deliverability": {
                    "status": "deliverable",
                    "status_detail": "valid_email",
                    "is_smtp_valid": True
                },
                "email_quality": {
                    "score": 0.8,
                    "is_free_email": False,
                    "is_disposable": False,
                    "is_role": True,
                    "is_username_suspicious": False
                },
                "email_sender": {
                    "organization_name": "Google LLC"
                },
                "email_domain": {
                    "domain": "google.com",
                    "domain_age": 10650
                },
                "email_risk": {
                    "address_risk_status": "low"
                },
                "email_breaches": {
                    "total_breaches": 11,
                    "date_last_breached": "2025-04-11"
                },
                "deliverability": "DELIVERABLE",
                "quality_score": 0.8,
                "is_smtp_valid": {"value": True, "label": "Valid (SMTP Accepted)"},
                "is_free_email": {"value": False, "label": "Corporate Domain"},
                "is_disposable_email": {"value": False, "label": "Non-Disposable"}
            }
        }

        res = self.client.post("/api/analyze", json={"email": "security@google.com"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])

        # Check structured JSON fields
        self.assertEqual(data["domain"], "google.com")
        self.assertEqual(data["mx_status"], "Found")
        self.assertIsInstance(data["mx_records"], list)
        self.assertEqual(data["mx_records"][0]["host"], "smtp.google.com")
        self.assertEqual(data["spf_status"], "Found")
        self.assertEqual(data["dmarc_status"], "Found")

        # Check Abstract API data
        self.assertEqual(data["abstract_api"]["status"], "Available")
        self.assertEqual(data["summary"]["deliverability"]["status"], "DELIVERABLE")
        self.assertEqual(data["summary"]["disposable"], "Non-Disposable")

        # Check reputation card view
        self.assertEqual(data["reputation"]["status"], "Available")
        self.assertIn("LOW RISK", data["reputation"]["data"]["reputation"])
        self.assertIn("11 Breach Record", data["reputation"]["data"]["breach_summary"])


class TestIntelBase(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_intelbase_not_configured(self):
        """IntelBase returns 'Not Configured' if key is empty."""
        res = query_intelbase_email("target@example.com", api_key="")
        self.assertEqual(res["status"], "Not Configured")
        self.assertFalse(res["is_configured"])
        self.assertIsNone(res["data"])

    def test_intelbase_invalid_email(self):
        """IntelBase rejects invalid email without network call."""
        res = query_intelbase_email("bad..format@", api_key="test_key_123")
        self.assertEqual(res["status"], "Invalid Email")
        self.assertIn("Syntax invalid", res["message"])
        self.assertIsNone(res["data"])

    @patch("requests.post")
    def test_intelbase_success(self, mock_post):
        """IntelBase successfully parses registered accounts, breaches, stealer logs, and scores."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "identifier": {
                "accounts": [
                    {
                        "module": {"name": "google", "name_formatted": "Google", "domain": "google.com"},
                        "data": {"username": "targetuser", "full_name": "Target User"}
                    }
                ]
            },
            "validator": {
                "registered": [
                    {"name": "google", "name_formatted": "Google", "domain": "google.com"},
                    {"name": "spotify", "name_formatted": "Spotify", "domain": "spotify.com"}
                ],
                "unregistered": []
            },
            "data_breaches": {
                "amount": 3,
                "sources": 2,
                "results": [{"email": "target@example.com", "source": {"name": "TestBreach", "date": "2024-01"}}]
            },
            "stealer_logs": {
                "count": 1,
                "compromised": True,
                "results": [{"origin": "https://accounts.google.com"}]
            },
            "insights": {
                "score": {
                    "authenticity": {"score": 85, "band": "high"},
                    "exposure": {"score": 62, "band": "moderate"}
                }
            },
            "meta": {
                "email": "target@example.com",
                "timeline": [{"name": "Google", "date": "2018-01-01"}]
            }
        }
        mock_post.return_value = mock_resp

        res = query_intelbase_email("target@example.com", api_key="valid_key")
        self.assertEqual(res["status"], "Available")
        self.assertTrue(res["is_configured"])
        data = res["data"]
        self.assertEqual(data["accounts_count"], 1)
        self.assertEqual(data["registered_count"], 2)
        self.assertEqual(data["breaches"]["amount"], 3)
        self.assertTrue(data["stealer_logs"]["compromised"])
        self.assertEqual(data["authenticity_score"], 85)
        self.assertEqual(data["exposure_score"], 62)

    @patch("requests.post")
    def test_intelbase_401_unauthorized(self, mock_post):
        """IntelBase returns Unauthorized on 401 (e.g. unwhitelisted IP or invalid key)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"error": "Your IP is not whitelisted."}
        mock_post.return_value = mock_resp

        res = query_intelbase_email("target@example.com", api_key="key_123")
        self.assertEqual(res["status"], "Unauthorized")
        self.assertIn("not whitelisted", res["message"])

    @patch("requests.post")
    def test_intelbase_429_quota(self, mock_post):
        """IntelBase returns Quota Exceeded on 429."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_post.return_value = mock_resp

        res = query_intelbase_email("target@example.com", api_key="key_123")
        self.assertEqual(res["status"], "Quota Exceeded")

    @patch("requests.post")
    def test_intelbase_timeout(self, mock_post):
        """IntelBase handles network timeouts gracefully."""
        mock_post.side_effect = requests.exceptions.Timeout("Read timeout")

        res = query_intelbase_email("target@example.com", api_key="key_123")
        self.assertEqual(res["status"], "API Unavailable")
        self.assertIn("timed out", res["message"])

    @patch("requests.get")
    def test_intelbase_egress_ip_endpoint(self, mock_get):
        """Verify /api/intelbase/ip debug endpoint."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ip": "203.0.113.24"}
        mock_get.return_value = mock_resp

        resp = self.client.get("/api/intelbase/ip")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["ip"], "203.0.113.24")


class TestBehindTheEmail(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_bte_not_configured(self):
        """Behind the Email returns Not Configured if token is empty."""
        res = query_behind_the_email("test@example.com", api_key="")
        self.assertEqual(res["status"], "Not Configured")
        self.assertFalse(res["is_configured"])
        self.assertIsNone(res["data"])

    def test_bte_invalid_email(self):
        """Behind the Email rejects malformed emails without HTTP query."""
        res = query_behind_the_email("invalid..email@", api_key="BTE_token")
        self.assertEqual(res["status"], "Invalid Email")
        self.assertIsNone(res["data"])

    @patch("requests.post")
    def test_bte_success_200(self, mock_post):
        """Behind the Email parses profile data correctly on HTTP 200."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "status": "found",
                "profile": {
                    "linkedIn": {
                        "basic": {
                            "displayName": "Golla Santhosh",
                            "headline": "B-TECH STUDENT | Cyber security Enthusiast",
                            "location": "Hyderabad, Telangana, India"
                        }
                    },
                    "google": {
                        "person": {
                            "personName": "Golla Santhosh",
                            "userType": "Personal"
                        }
                    },
                    "github": {
                        "name": "Golla Santhosh",
                        "username": "gollasanthosh",
                        "followers": 5,
                        "bio": "Problem-solving Engineer"
                    },
                    "summary": {
                        "names": [{"value": "Golla Santhosh", "source": "linkedin"}],
                        "locations": [{"value": "Hyderabad, Telangana, India", "source": "linkedin"}],
                        "dates": [{"value": "Nov 14, 2026", "label": "Last active", "source": "google"}]
                    }
                }
            }
        }
        mock_post.return_value = mock_resp

        res = query_behind_the_email("gollasanthosh19@gmail.com", api_key="BTE_valid_token")
        self.assertEqual(res["status"], "Available")
        self.assertTrue(res["is_configured"])
        data = res["data"]
        self.assertEqual(data["full_name"], "Golla Santhosh")
        self.assertEqual(data["location"], "Hyderabad, Telangana, India")
        self.assertGreaterEqual(data["accounts_count"], 3)

    @patch("requests.post")
    def test_bte_plan_restricted_401(self, mock_post):
        """Behind the Email handles 401 with clean status and no fake/mock data."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {
            "error": {"message": "You do not have access to use this route."}
        }
        mock_post.return_value = mock_resp

        res = query_behind_the_email("gollasanthosh19@gmail.com", api_key="BTE_free_token")
        self.assertIn("Plan Restricted", res["status"])
        self.assertTrue(res["is_configured"])
        self.assertIsNone(res["data"])

    @patch("requests.post")
    def test_bte_timeout(self, mock_post):
        """Behind the Email handles timeouts safely."""
        mock_post.side_effect = requests.exceptions.Timeout("Read timeout")

        res = query_behind_the_email("target@example.com", api_key="BTE_token")
        self.assertEqual(res["status"], "API Unavailable")

    @patch("requests.get")
    def test_bte_health_endpoint(self, mock_get):
        """Behind the Email health endpoint works."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"version": "1.0", "timestamp": "2026-11-16T12:00:00Z"}}
        mock_get.return_value = mock_resp

        resp = self.client.get("/api/bte/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])


class TestOsintDiscovery(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    @patch("services.dns_analyzer.check_mx")
    def test_analyze_domain_without_mx_halts_social_checks(self, mock_mx):
        """When domain has no MX records, mark as undeliverable and halt social checks."""
        mock_mx.return_value = {
            "status": "Not Found",
            "records": [],
            "primary_mx": None,
            "error": "No MX records found"
        }

        res = self.client.post("/api/analyze", json={"email": "test@neverssl.com"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["mx_status"], "Not Found")
        self.assertEqual(data["summary"]["deliverability"]["status"], "UNDELIVERABLE")
        self.assertEqual(data["osint"]["accounts_count"], 0)
        self.assertIn("Social account checks aborted", data["osint"]["message"])

    @patch("requests.get")
    def test_gravatar_200_found(self, mock_get):
        """Gravatar returns real profile details when HTTP 200."""
        def get_side_effect(url, headers=None, timeout=None):
            resp = MagicMock()
            if ".json" in url:
                resp.status_code = 200
                resp.json.return_value = {
                    "entry": [{
                        "displayName": "Test User",
                        "preferredUsername": "testuser",
                        "currentLocation": "San Francisco, CA",
                        "thumbnailUrl": "https://gravatar.com/avatar/test.jpg"
                    }]
                }
            else:
                resp.status_code = 200
            return resp

        mock_get.side_effect = get_side_effect
        res = check_gravatar("user@example.com")
        self.assertTrue(res["found"])
        self.assertEqual(res["display_name"], "Test User")
        self.assertEqual(res["location"], "San Francisco, CA")

    @patch("requests.get")
    def test_gravatar_404_not_found(self, mock_get):
        """Gravatar returns found=False on 404."""
        resp = MagicMock()
        resp.status_code = 404
        mock_get.return_value = resp

        res = check_gravatar("nonexistent@example.com")
        self.assertFalse(res["found"])
        self.assertIsNone(res["display_name"])

    @patch("requests.get")
    def test_github_user_found(self, mock_get):
        """GitHub search returns real user match and profile details."""
        def gh_side_effect(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.status_code = 200
            if "search/users" in url:
                resp.json.return_value = {
                    "total_count": 1,
                    "items": [{"login": "octocat", "avatar_url": "https://github.com/octocat.png"}]
                }
            elif "users/octocat" in url:
                resp.json.return_value = {
                    "login": "octocat",
                    "name": "The Octocat",
                    "avatar_url": "https://github.com/octocat.png",
                    "followers": 5000,
                    "following": 10,
                    "public_repos": 8,
                    "created_at": "2011-01-25T18:44:36Z"
                }
            return resp

        mock_get.side_effect = gh_side_effect
        res = check_github("octocat@github.com")
        self.assertTrue(res["found"])
        self.assertEqual(res["username"], "octocat")
        self.assertEqual(res["name"], "The Octocat")
        self.assertEqual(res["followers"], 5000)

    @patch("requests.get")
    def test_github_user_not_found(self, mock_get):
        """GitHub search returns found=False when total_count is 0."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"total_count": 0, "items": []}
        mock_get.return_value = resp

        res = check_github("nobody@example.com")
        self.assertFalse(res["found"])
        self.assertIsNone(res["username"])

    @patch("services.intelbase.requests.post")
    def test_intelbase_email_lookup_success(self, mock_post):
        """Test IntelBase email lookup parses accounts, breaches, and stealers."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "identifier": {
                "accounts": [
                    {
                        "module": {
                            "id": "5f9a",
                            "name": "google",
                            "name_formatted": "Google",
                            "domain": "google.com",
                            "type": 0
                        },
                        "data": {
                            "username": "targetuser",
                            "full_name": "Target User",
                            "avatar_url": "https://example.com/photo.jpg",
                            "creation_date": "2016-04-12T00:00:00Z"
                        }
                    }
                ]
            },
            "validator": {
                "registered": [
                    {"id": "mod1", "name": "google", "name_formatted": "Google", "domain": "google.com", "type": 0},
                    {"id": "mod2", "name": "spotify", "name_formatted": "Spotify", "domain": "spotify.com", "type": 1}
                ],
                "unregistered": [
                    {"id": "mod3", "name": "duolingo", "name_formatted": "Duolingo", "domain": "duolingo.com", "type": 1}
                ]
            },
            "data_breaches": {
                "amount": 3,
                "sources": 2,
                "results": [
                    {
                        "email": "target@example.com",
                        "username": "targetuser",
                        "source": {"name": "ExampleBreach", "date": "2021-06"}
                    }
                ],
                "redacted": False
            },
            "stealer_logs": {
                "count": 1,
                "compromised": True,
                "has_stealer_log_type": True,
                "results": [
                    {
                        "data_type": "stealerlog",
                        "origin": "https://accounts.google.com",
                        "login": "target@example.com"
                    }
                ]
            },
            "insights": {
                "score": {
                    "authenticity": {"score": 85, "band": "high"},
                    "exposure": {"score": 45, "band": "moderate"}
                }
            },
            "meta": {
                "email": "target@example.com",
                "timeline": [
                    {"source": "creation_date", "name": "Google", "date": "2016-04-12T00:00:00Z"}
                ]
            }
        }
        mock_post.return_value = mock_resp

        res = query_intelbase_email("target@example.com", api_key="test_key")
        self.assertEqual(res["status"], "Available")
        self.assertTrue(res["is_configured"])
        data = res["data"]
        self.assertEqual(data["accounts_count"], 1)
        self.assertEqual(data["registered_count"], 2)
        self.assertEqual(data["breaches"]["amount"], 3)
        self.assertEqual(data["stealer_logs"]["count"], 1)
        self.assertTrue(data["stealer_logs"]["compromised"])
        self.assertEqual(data["authenticity_score"], 85)
        self.assertEqual(data["exposure_score"], 45)

    @patch("services.intelbase.requests.post")
    def test_intelbase_unauthorized_ip(self, mock_post):
        """Test IntelBase handles 401 unwhitelisted IP error gracefully."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"error": "Your IP is not whitelisted."}
        mock_post.return_value = mock_resp

        res = query_intelbase_email("target@example.com", api_key="test_key")
        self.assertEqual(res["status"], "Unauthorized")
        self.assertIn("Your IP is not whitelisted", res["message"])
        self.assertIsNone(res["data"])

    @patch("services.intelbase.requests.get")
    def test_intelbase_egress_ip(self, mock_get):
        """Test IntelBase /account/ip helper returns current IP."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ip": "203.0.113.24"}
        mock_get.return_value = mock_resp

        res = get_intelbase_egress_ip()
        self.assertTrue(res["success"])
        self.assertEqual(res["ip"], "203.0.113.24")

    @patch("services.hibp_analyzer.requests.get")
    def test_hibp_service_account_exists(self, mock_get):
        """Test HIBP returns authentic breach records for official test account."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "PwnCount": 152445165,
                "Description": "In October 2013, 153 million Adobe accounts were breached...",
                "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
                "IsVerified": True
            }
        ]
        mock_get.return_value = mock_resp

        res = check_hibp_breaches("account-exists@hibp-integration-tests.com", user_authorized=True)
        self.assertEqual(res["status"], "Found")
        self.assertEqual(res["breach_count"], 1)
        self.assertEqual(res["breaches"][0]["name"], "Adobe")
        self.assertEqual(res["breaches"][0]["domain"], "adobe.com")
        self.assertIn("Passwords", res["breaches"][0]["data_classes"])
        self.assertIn("Have I Been Pwned", res["source"])

    @patch("services.hibp_analyzer.requests.get")
    def test_hibp_service_404_no_breaches(self, mock_get):
        """Test HIBP handles HTTP 404 as zero publicly listed breaches."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        res = check_hibp_breaches("clean-user@hibp-integration-tests.com", user_authorized=True)
        self.assertEqual(res["status"], "Not Found")
        self.assertEqual(res["breach_count"], 0)
        self.assertEqual(len(res["breaches"]), 0)
        self.assertIn("No publicly disclosed breach records", res["message"])

    def test_hibp_service_unauthorized_consent(self):
        """Test HIBP halts when user authorization is not granted."""
        res = check_hibp_breaches("account-exists@hibp-integration-tests.com", user_authorized=False)
        self.assertEqual(res["status"], "Unauthorized Check")
        self.assertEqual(res["breach_count"], 0)
        self.assertIn("User authorization is required", res["message"])

    @patch("services.hibp_analyzer.requests.get")
    def test_hibp_service_http_errors(self, mock_get):
        """Test HIBP 401, 403, 429, and 503 response handling."""
        # 401
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp
        res = check_hibp_breaches("test@example.com", api_key="bad_key")
        self.assertEqual(res["status"], "Unauthorized")

        # 403
        mock_resp.status_code = 403
        res = check_hibp_breaches("test@example.com", api_key="bad_key")
        self.assertEqual(res["status"], "Forbidden")

        # 429
        mock_resp.status_code = 429
        mock_resp.headers = {"retry-after": "5"}
        res = check_hibp_breaches("test@example.com", api_key="bad_key")
        self.assertEqual(res["status"], "Rate Limited")
        self.assertEqual(res["retry_after"], "5")

        # 503
        mock_resp.status_code = 503
        res = check_hibp_breaches("test@example.com", api_key="bad_key")
        self.assertEqual(res["status"], "Service Unavailable")

    @patch("services.hibp_analyzer.requests.get")
    def test_hibp_api_endpoint_authorized(self, mock_get):
        """Test POST /api/breach-check endpoint with official test email."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "PwnCount": 152445165,
                "DataClasses": ["Email addresses", "Passwords"]
            }
        ]
        mock_get.return_value = mock_resp

        resp = self.client.post("/api/breach-check", json={
            "email": "account-exists@hibp-integration-tests.com",
            "authorized": True
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "Found")
        self.assertEqual(data["breach_count"], 1)
        self.assertEqual(data["breaches"][0]["name"], "Adobe")
        self.assertIn("Have I Been Pwned", data["source"])

    def test_hibp_api_endpoint_unauthorized(self):
        """Test POST /api/breach-check returns 403 when authorized is false."""
        resp = self.client.post("/api/breach-check", json={
            "email": "target@example.com",
            "authorized": False
        })
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("User authorization is required", data["error"])

    def test_hibp_api_endpoint_invalid_syntax(self):
        """Test POST /api/breach-check returns 400 for invalid email."""
        resp = self.client.post("/api/breach-check", json={
            "email": "bad_email_format",
            "authorized": True
        })
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Invalid email format", data["error"])


if __name__ == "__main__":
    unittest.main()
