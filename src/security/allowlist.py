import re
from urllib.parse import urlparse
from typing import Tuple, Optional
from ..database.db import Database
from ..database.models import ApprovedSite


def normalize_domain(input_target: str) -> str:
    """
    Extract and clean the domain from user input.
    Strips http/https protocols, ports, URL paths, query parameters, and trailing slashes.
    Example: 'https://sub.example.com:8443/login?q=1' -> 'sub.example.com'
    """
    target = input_target.strip()
    if not target:
        return ""

    # Prepend scheme if missing so urlparse parses netloc reliably
    if not re.match(r"^[a-zA-Z]+://", target):
        target = "https://" + target

    parsed = urlparse(target)
    hostname = parsed.hostname or parsed.netloc

    # Remove port if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    hostname = hostname.strip().lower()
    return hostname


class AllowlistService:
    def __init__(self, db: Database):
        self.db = db

    async def check_and_authorize(self, input_target: str, user_id: int) -> Tuple[bool, str, Optional[ApprovedSite]]:
        """
        Validates target against the approved allowlist.
        Returns:
            (is_allowed, message, approved_site_record)
        Logs every attempt to the audit table regardless of success or failure.
        """
        domain = normalize_domain(input_target)
        if not domain:
            await self.db.add_audit_log(
                target_domain="<empty>",
                user_id=user_id,
                action="SCAN_REQUEST",
                allowed=False,
                reason="Target domain is empty or invalid"
            )
            return False, "❌ Target domain cannot be empty or invalid.", None

        # Basic domain format validation (valid RFC hostname characters)
        domain_pattern = r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        # Support localhost/127.0.0.1 for local lab/staging environments
        is_local = domain in ("localhost", "127.0.0.1")
        if not is_local and not re.match(domain_pattern, domain):
            await self.db.add_audit_log(
                target_domain=domain,
                user_id=user_id,
                action="SCAN_REQUEST",
                allowed=False,
                reason="Invalid domain syntax"
            )
            return False, f"❌ '{domain}' does not appear to be a valid domain format.", None

        site = await self.db.get_approved_site(domain)
        if not site:
            await self.db.add_audit_log(
                target_domain=domain,
                user_id=user_id,
                action="SCAN_REQUEST",
                allowed=False,
                reason="Domain not in approved_sites allowlist"
            )
            msg = (
                f"⛔ **Authorization Denied: Target Not Approved**\n\n"
                f"The domain `{domain}` is not in your pre-approved sites list.\n"
                f"By hard policy, scans are strictly forbidden against unauthorized targets.\n\n"
                f"To add an authorized domain (your own project or under written client agreement):\n"
                f"`/addsite {domain} <authorization note>`"
            )
            return False, msg, None

        # Site is approved
        await self.db.add_audit_log(
            target_domain=domain,
            user_id=user_id,
            action="SCAN_REQUEST",
            allowed=True,
            reason=f"Approved on basis: {site.note}"
        )
        return True, domain, site
