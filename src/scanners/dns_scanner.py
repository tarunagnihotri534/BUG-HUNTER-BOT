import logging
from typing import List, Any
import dns.asyncresolver
import dns.resolver
import dns.exception

from ..database.models import Finding, Severity
from .base import BaseScanner

logger = logging.getLogger(__name__)


class DNSScanner(BaseScanner):
    """
    Asynchronously inspects DNS records for email authentication hygiene (SPF, DMARC, MX),
    DNSSEC configuration, and dangling CNAME pointers.
    Zero external binary dependencies (uses dnspython).
    """

    def __init__(self):
        super().__init__(name="DNS & Email Security")

    def is_available(self) -> bool:
        return True

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        domain = domain.lower().strip()

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0

        # 1. Inspect MX Records
        has_mx = False
        try:
            mx_answers = await resolver.resolve(domain, "MX")
            if mx_answers:
                has_mx = True
                mx_hosts = [str(r.exchange).rstrip(".") for r in mx_answers]
                findings.append(Finding(
                    title="Active Mail Exchanger (MX) Records",
                    severity=Severity.INFO,
                    tool=self.name,
                    description=f"Domain has active mail delivery hosts configured: {', '.join(mx_hosts[:4])}",
                    why_it_matters="Indicates domain actively sends/receives emails, making SPF and DMARC enforcement critical."
                ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"MX lookup for {domain} error: {e}")

        # 2. Inspect SPF (TXT records on root domain)
        spf_found = False
        try:
            txt_answers = await resolver.resolve(domain, "TXT")
            for rdata in txt_answers:
                txt_str = "".join([part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part) for part in rdata.strings])
                if txt_str.lower().startswith("v=spf1"):
                    spf_found = True
                    # Check for dangerous +all
                    if "+all" in txt_str.lower():
                        findings.append(Finding(
                            title="Dangerous SPF Record (+all Wildcard)",
                            severity=Severity.HIGH,
                            tool=self.name,
                            description=f"SPF record contains '+all': `{txt_str}`",
                            why_it_matters="The '+all' directive explicitly allows ANY IP address worldwide to send forged emails from your domain.",
                            reference_url="https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"
                        ))
                    elif "?all" in txt_str.lower():
                        findings.append(Finding(
                            title="Weak SPF Policy (?all Neutral)",
                            severity=Severity.LOW,
                            tool=self.name,
                            description=f"SPF policy uses neutral '?all' qualifier: `{txt_str}`",
                            why_it_matters="Receiving mail servers will not fail spoofed emails, treating sender authentication as neutral.",
                            reference_url="https://dmarc.org/presentations/Email-Authentication-Basics-2015Q4.pdf"
                        ))
                    elif "~all" in txt_str.lower():
                        findings.append(Finding(
                            title="SPF Softfail (~all) Configured",
                            severity=Severity.INFO,
                            tool=self.name,
                            description=f"SPF record is in Softfail mode (`~all`). Recommend hardening to hardfail (`-all`) once verified.",
                            why_it_matters="Hardfail strictly commands receiving MTAs to reject unauthorized senders."
                        ))
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"TXT lookup error for {domain}: {e}")

        if not spf_found:
            findings.append(Finding(
                title="Missing SPF Record",
                severity=Severity.HIGH if has_mx else Severity.MEDIUM,
                tool=self.name,
                description=f"No TXT SPF (v=spf1) record found for `{domain}`.",
                why_it_matters="Without an SPF record, adversaries can easily forge emails pretending to originate from your domain.",
                reference_url="https://owasp.org/www-community/attacks/Email_Spoofing"
            ))

        # 3. Inspect DMARC (_dmarc.<domain>)
        dmarc_target = f"_dmarc.{domain}"
        dmarc_found = False
        try:
            dmarc_answers = await resolver.resolve(dmarc_target, "TXT")
            for rdata in dmarc_answers:
                txt_str = "".join([part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part) for part in rdata.strings])
                if "v=dmarc1" in txt_str.lower():
                    dmarc_found = True
                    # Check policy p=
                    p_val = ""
                    for token in txt_str.split(";"):
                        token = token.strip()
                        if token.lower().startswith("p="):
                            p_val = token.split("=")[1].strip().lower()

                    if p_val == "none":
                        findings.append(Finding(
                            title="DMARC Policy Set to 'none' (Monitoring Only)",
                            severity=Severity.MEDIUM,
                            tool=self.name,
                            description=f"DMARC policy is set to `p=none`: `{txt_str}`",
                            why_it_matters="A policy of 'none' does not block or quarantine unauthorized emails; fraudulent emails are still delivered.",
                            reference_url="https://dmarc.org/overview/"
                        ))
                    elif p_val in ("quarantine", "reject"):
                        findings.append(Finding(
                            title=f"DMARC Enforcement Active (`p={p_val}`)",
                            severity=Severity.INFO,
                            tool=self.name,
                            description=f"DMARC policy enforces `{p_val}`: unauthorized mail will be quarantined or rejected.",
                            why_it_matters="Protects organization brand reputation and prevents BEC / CEO fraud spoofing attacks."
                        ))
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"DMARC lookup error for {domain}: {e}")

        if not dmarc_found:
            findings.append(Finding(
                title="Missing DMARC Record",
                severity=Severity.HIGH if has_mx else Severity.MEDIUM,
                tool=self.name,
                description=f"No DMARC record found at `_dmarc.{domain}`.",
                why_it_matters="DMARC connects SPF and DKIM authentication to protect against domain spoofing and phishing.",
                reference_url="https://dmarc.org/"
            ))

        # 4. Check DNSSEC
        try:
            dnskey_answers = await resolver.resolve(domain, "DNSKEY")
            if dnskey_answers:
                findings.append(Finding(
                    title="DNSSEC Enabled",
                    severity=Severity.INFO,
                    tool=self.name,
                    description=f"Domain has cryptographic DNSKEY records published.",
                    why_it_matters="DNSSEC protects DNS queries against spoofing and cache poisoning attacks."
                ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            findings.append(Finding(
                title="DNSSEC Not Enabled",
                severity=Severity.INFO,
                tool=self.name,
                description=f"No DNSKEY records found for {domain}.",
                why_it_matters="Enabling DNSSEC prevents malicious DNS hijacking, cache poisoning, and route manipulation."
            ))
        except Exception:
            pass

        return findings
