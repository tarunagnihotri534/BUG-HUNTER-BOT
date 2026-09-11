import logging
from typing import List, Any
import httpx

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)

BUCKET_SUFFIXES = [
    "",
    "-assets",
    "-static",
    "-public",
    "-media",
    "-data",
    "-backup",
    "-files",
    "-prod",
    "-staging"
]


class BucketExposureScanner(BaseScanner):
    """
    Cloud Storage Bucket Exposure Discovery.
    Generates common naming permutations from target domain/company name,
    checks AWS S3, Google Cloud Storage (GCS), and Azure Blob Storage for public
    listing or read permissions, and flags open buckets as CRITICAL.
    """

    def __init__(self):
        super().__init__(name="Cloud Storage Bucket Exposure")

    def is_available(self) -> bool:
        return True

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        domain = domain.lower().strip()
        # Clean domain to base name (e.g. example.com -> example)
        base_name = domain.split(".")[0]

        headers = {"User-Agent": "CyberSentinel-SecurityAudit/2.0"}
        async with httpx.AsyncClient(headers=headers, timeout=5.0, follow_redirects=True) as client:
            for suffix in BUCKET_SUFFIXES:
                bucket_name = f"{base_name}{suffix}"

                # 1. AWS S3 check
                s3_url = f"https://{bucket_name}.s3.amazonaws.com"
                try:
                    res = await client.get(s3_url)
                    if res.status_code == 200 and "<ListBucketResult" in res.text:
                        findings.append(Finding(
                            title=f"Publicly Listable AWS S3 Bucket: `{bucket_name}`",
                            severity=Severity.CRITICAL,
                            tool=self.name,
                            description=(
                                f"AWS S3 Bucket `{bucket_name}` at `{s3_url}` allows anonymous public listing (`AllUsers`). "
                                f"Objects and file contents can be browsed and downloaded."
                            ),
                            why_it_matters=(
                                "Severe data exposure risk. Attackers can download sensitive customer data, backups, "
                                "source code, or proprietary documents."
                            ),
                            reference_url="https://cwe.mitre.org/data/definitions/276.html",
                            endpoint=s3_url,
                            steps_to_reproduce=f"Send an anonymous HTTP GET request to `{s3_url}` and inspect the XML ListBucketResult.",
                            remediation="Enable S3 Block Public Access across the AWS bucket and account. Restrict bucket ACLs and policies to authorized IAM identities only."
                        ))
                    elif res.status_code == 403:
                        # Bucket exists but is protected
                        logger.debug(f"Bucket {bucket_name} exists but is protected (403).")
                except Exception:
                    pass

                # 2. Google Cloud Storage (GCS) check
                gcs_url = f"https://storage.googleapis.com/{bucket_name}"
                try:
                    res = await client.get(gcs_url)
                    if res.status_code == 200 and "<ListBucketResult" in res.text:
                        findings.append(Finding(
                            title=f"Publicly Listable Google Cloud Storage Bucket: `{bucket_name}`",
                            severity=Severity.CRITICAL,
                            tool=self.name,
                            description=f"GCS Bucket at `{gcs_url}` is publicly readable and listable by anonymous users.",
                            why_it_matters="Allows unauthorized enumeration and exfiltration of cloud-hosted assets and backups.",
                            reference_url="https://cloud.google.com/storage/docs/access-control/making-data-public",
                            endpoint=gcs_url,
                            steps_to_reproduce=f"Send an HTTP GET request to `{gcs_url}`.",
                            remediation="Remove 'allUsers' and 'allAuthenticatedUsers' from GCS bucket IAM roles."
                        ))
                except Exception:
                    pass

                # 3. Azure Blob Storage check
                azure_url = f"https://{bucket_name}.blob.core.windows.net/?comp=list"
                try:
                    res = await client.get(azure_url)
                    if res.status_code == 200 and "<EnumerationResults" in res.text:
                        findings.append(Finding(
                            title=f"Publicly Listable Azure Blob Container: `{bucket_name}`",
                            severity=Severity.CRITICAL,
                            tool=self.name,
                            description=f"Azure Blob Storage container at `{azure_url}` permits anonymous public read/list access.",
                            why_it_matters="Direct exposure of cloud storage containers to internet-wide scraping and data breaches.",
                            reference_url="https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure",
                            endpoint=azure_url,
                            steps_to_reproduce=f"Send an HTTP GET request to `{azure_url}`.",
                            remediation="Set Azure Storage container public access level to 'Private (no anonymous access)'."
                        ))
                except Exception:
                    pass

        return findings
