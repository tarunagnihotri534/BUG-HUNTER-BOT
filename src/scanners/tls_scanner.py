import asyncio
import datetime
import logging
import socket
import ssl
from typing import List, Any
import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)


class TLSScanner(BaseScanner):
    """
    TLS/SSL configuration and certificate health scanner.
    Performs certificate expiry audits, hostname validation, deprecated protocol checks,
    and HTTP Strict Transport Security (HSTS) verification.
    """

    def __init__(self, custom_bin_path: str = ""):
        super().__init__(name="TLS/SSL Health", custom_bin_path=custom_bin_path)

    def is_available(self) -> bool:
        # Native TLS audit capabilities are always available via Python's ssl & cryptography
        return True

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        port = kwargs.get("port", 443)

        # 1. Certificate inspection & validity audit
        cert_findings = await asyncio.to_thread(self._check_certificate, domain, port)
        findings.extend(cert_findings)

        # 2. Protocol version audit (Deprecated TLS 1.0 / TLS 1.1)
        protocol_findings = await asyncio.to_thread(self._check_deprecated_protocols, domain, port)
        findings.extend(protocol_findings)

        # 3. HSTS & HTTPS enforcement audit
        hsts_findings = await self._check_hsts(domain)
        findings.extend(hsts_findings)

        return findings

    def _check_certificate(self, domain: str, port: int) -> List[Finding]:
        findings: List[Finding] = []
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        findings.append(Finding(
                            title="No TLS Certificate Received",
                            severity=Severity.HIGH,
                            tool=self.name,
                            description=f"Server at {domain}:{port} returned an empty certificate.",
                            why_it_matters="Without a valid certificate, traffic cannot be encrypted and trusted by users.",
                            reference_url="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                        ))
                        return findings

                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Expiry check
                    now = datetime.datetime.now(datetime.timezone.utc)
                    not_after = cert.not_valid_after_utc
                    days_remaining = (not_after - now).days

                    if days_remaining < 0:
                        findings.append(Finding(
                            title="TLS Certificate Has Expired",
                            severity=Severity.CRITICAL,
                            tool=self.name,
                            description=f"The certificate for {domain} expired on {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')} ({abs(days_remaining)} days ago).",
                            why_it_matters="Browsers will display full-page security warnings, blocking normal user access.",
                            reference_url="https://cwe.mitre.org/data/definitions/295.html",
                            raw_data={"expiry": not_after.isoformat(), "days_remaining": days_remaining}
                        ))
                    elif days_remaining <= 14:
                        findings.append(Finding(
                            title=f"TLS Certificate Expiring Soon ({days_remaining} days)",
                            severity=Severity.HIGH,
                            tool=self.name,
                            description=f"The certificate for {domain} will expire in {days_remaining} days on {not_after.strftime('%Y-%m-%d')}.",
                            why_it_matters="Failure to renew in time will cause immediate site outages and browser security warnings.",
                            reference_url="https://cwe.mitre.org/data/definitions/295.html",
                            raw_data={"expiry": not_after.isoformat(), "days_remaining": days_remaining}
                        ))
                    elif days_remaining <= 30:
                        findings.append(Finding(
                            title=f"TLS Certificate Renewal Window Approaching ({days_remaining} days left)",
                            severity=Severity.MEDIUM,
                            tool=self.name,
                            description=f"The certificate for {domain} expires in {days_remaining} days.",
                            why_it_matters="Verify that automated certificate renewal (e.g., Certbot / Let's Encrypt) is configured and working.",
                            reference_url="https://cwe.mitre.org/data/definitions/295.html",
                            raw_data={"expiry": not_after.isoformat(), "days_remaining": days_remaining}
                        ))
                    else:
                        findings.append(Finding(
                            title=f"Valid TLS Certificate ({days_remaining} days remaining)",
                            severity=Severity.INFO,
                            tool=self.name,
                            description=f"Certificate valid until {not_after.strftime('%Y-%m-%d')}. Issuer: {cert.issuer.rfc4514_string()}.",
                            why_it_matters="Certificate is valid and within safe operational limits.",
                            reference_url="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                            raw_data={"expiry": not_after.isoformat(), "issuer": cert.issuer.rfc4514_string()}
                        ))

        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                title="TLS Certificate Validation Failed",
                severity=Severity.HIGH,
                tool=self.name,
                description=f"Certificate verification failed: {e.verify_message}",
                why_it_matters="Browsers will refuse to establish a trusted connection with untrusted or self-signed certificates.",
                reference_url="https://cwe.mitre.org/data/definitions/295.html",
                raw_data={"error": str(e)}
            ))
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            findings.append(Finding(
                title="TLS Connection Failed",
                severity=Severity.LOW,
                tool=self.name,
                description=f"Could not connect to {domain}:{port} over TLS: {str(e)}",
                why_it_matters="Ensure HTTPS service is running and accessible on port 443.",
                reference_url="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                raw_data={"error": str(e)}
            ))
        return findings

    def _check_deprecated_protocols(self, domain: str, port: int) -> List[Finding]:
        """Test if server negotiates deprecated TLS 1.0 or TLS 1.1."""
        findings: List[Finding] = []

        deprecated_versions = []
        if hasattr(ssl.TLSVersion, "TLSv1"):
            deprecated_versions.append(("TLS 1.0", ssl.TLSVersion.TLSv1))
        if hasattr(ssl.TLSVersion, "TLSv1_1"):
            deprecated_versions.append(("TLS 1.1", ssl.TLSVersion.TLSv1_1))

        for name, ver in deprecated_versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver
                ctx.maximum_version = ver

                with socket.create_connection((domain, port), timeout=4) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as _:
                        findings.append(Finding(
                            title=f"Deprecated Protocol Supported: {name}",
                            severity=Severity.MEDIUM,
                            tool=self.name,
                            description=f"The server negotiated connection using obsolete {name}.",
                            why_it_matters="Legacy TLS protocols (TLS 1.0 and TLS 1.1) are deprecated by RFC 8996 and susceptible to cryptographic attacks like BEAST and POODLE.",
                            reference_url="https://datatracker.ietf.org/doc/html/rfc8996",
                            raw_data={"deprecated_protocol": name}
                        ))
            except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
                # Connection refused or handshake failed for legacy version = secure behavior
                pass

        return findings

    async def _check_hsts(self, domain: str) -> List[Finding]:
        findings: List[Finding] = []
        url = f"https://{domain}"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                res = await client.get(url)
                hsts = res.headers.get("strict-transport-security")
                if not hsts:
                    findings.append(Finding(
                        title="Missing HTTP Strict Transport Security (HSTS)",
                        severity=Severity.MEDIUM,
                        tool=self.name,
                        description="The Strict-Transport-Security header was not present in HTTPS response.",
                        why_it_matters="HSTS instructs web browsers to only communicate over HTTPS, protecting against SSL-stripping and man-in-the-middle attacks.",
                        reference_url="https://owasp.org/www-project-secure-headers/#strict-transport-security"
                    ))
                else:
                    findings.append(Finding(
                        title="HSTS Header Configured",
                        severity=Severity.INFO,
                        tool=self.name,
                        description=f"HSTS header is present: {hsts}",
                        why_it_matters="Ensures client browsers enforce encrypted HTTPS connections.",
                        reference_url="https://owasp.org/www-project-secure-headers/#strict-transport-security",
                        raw_data={"hsts": hsts}
                    ))
        except Exception as e:
            logger.debug(f"HSTS check error for {domain}: {e}")

        return findings
