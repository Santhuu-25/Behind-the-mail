"""
MailRadar Services Package
Modules for DNS analysis, email syntax & API validation, reputation inspection, IntelBase OSINT, and HIBP breach analysis.
"""

from .dns_analyzer import check_mx, check_spf, check_dmarc, analyze_domain_dns
from .email_validator import validate_email_syntax, check_email_reputation, query_abstract_api
from .reputation import query_emailrep
from .intelbase import (
    query_intelbase_email,
    query_intelbase_username,
    get_intelbase_modules,
    get_intelbase_egress_ip
)
from .hibp_analyzer import check_hibp_breaches
from .behind_the_email import query_behind_the_email, check_bte_api_health
from .osint_scanner import check_gravatar, check_github, check_holehe_platforms
