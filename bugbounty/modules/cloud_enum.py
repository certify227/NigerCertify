"""Énumération cloud — S3, Azure, GCS, Firebase."""

from __future__ import annotations

import re
from typing import Any

import requests

from .utils import Finding, get_domain, normalize_url, safe_request

BUCKET_PATTERNS = [
    "{name}", "{name}-backup", "{name}-dev", "{name}-staging", "{name}-prod",
    "{name}-assets", "{name}-media", "{name}-static", "{name}-files",
    "{name}-uploads", "{name}-data", "{name}-logs", "{name}-public",
    "backup-{name}", "dev-{name}", "staging-{name}", "{name}.backup",
]


class CloudEnumerator:
    """Énumère les buckets cloud publics."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.domain = get_domain(self.target)
        self.session = session
        self.findings: list[Finding] = []
        self.buckets: list[dict[str, str]] = []

    def run_full_scan(self) -> list[Finding]:
        base_name = self.domain.split(".")[0]
        names = {base_name, self.domain.replace(".", "-"), self.domain.replace(".", "")}

        for name in names:
            for pattern in BUCKET_PATTERNS:
                bucket = pattern.format(name=name)
                self._check_s3(bucket)
                self._check_gcs(bucket)
                self._check_azure(bucket)

        self._check_firebase(base_name)
        return self.findings

    def _check_s3(self, bucket: str) -> None:
        for region in ("", ".s3.amazonaws.com", ".s3-us-west-2.amazonaws.com"):
            url = f"https://{bucket}{region}/"
            resp = safe_request(self.session, "GET", url)
            if resp and resp.status_code == 200 and ("ListBucketResult" in resp.text or "<Contents>" in resp.text):
                self.findings.append(
                    Finding(
                        title=f"Bucket S3 public: {bucket}",
                        severity="critical",
                        category="Cloud Exposure",
                        url=url,
                        description="Bucket S3 listable publiquement",
                        evidence=resp.text[:300],
                        remediation="Restreindre les ACL du bucket S3",
                    )
                )
                self.buckets.append({"type": "s3", "name": bucket, "url": url})
            elif resp and resp.status_code == 403:
                self.findings.append(
                    Finding(
                        title=f"Bucket S3 existant (403): {bucket}",
                        severity="info",
                        category="Cloud Exposure",
                        url=url,
                        description="Bucket existe mais accès refusé — tester ACL bypass",
                    )
                )

    def _check_gcs(self, bucket: str) -> None:
        url = f"https://storage.googleapis.com/{bucket}/"
        resp = safe_request(self.session, "GET", url)
        if resp and resp.status_code == 200 and ("ListBucket" in resp.text or "<Key>" in resp.text):
            self.findings.append(
                Finding(
                    title=f"Bucket GCS public: {bucket}",
                    severity="critical",
                    category="Cloud Exposure",
                    url=url,
                    description="Bucket Google Cloud Storage public",
                    evidence=resp.text[:300],
                )
            )

    def _check_azure(self, bucket: str) -> None:
        url = f"https://{bucket}.blob.core.windows.net/?restype=container&comp=list"
        resp = safe_request(self.session, "GET", url)
        if resp and resp.status_code == 200 and "EnumerationResults" in resp.text:
            self.findings.append(
                Finding(
                    title=f"Blob Azure public: {bucket}",
                    severity="critical",
                    category="Cloud Exposure",
                    url=url,
                    description="Container Azure Blob listable",
                    evidence=resp.text[:300],
                )
            )

    def _check_firebase(self, name: str) -> None:
        url = f"https://{name}.firebaseio.com/.json"
        resp = safe_request(self.session, "GET", url)
        if resp and resp.status_code == 200 and resp.text not in ("null", "{}", ""):
            self.findings.append(
                Finding(
                    title=f"Firebase DB exposée: {name}",
                    severity="critical",
                    category="Cloud Exposure",
                    url=url,
                    description="Base Firebase accessible sans auth",
                    evidence=resp.text[:300],
                    remediation="Configurer les règles de sécurité Firebase",
                )
            )
