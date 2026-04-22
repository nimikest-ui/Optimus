"""NVD (National Vulnerability Database) ingester."""

import requests
import json
from typing import Dict, List, Any
from kb.ingesters.base_ingester import BaseIngester


class NVDIngester(BaseIngester):
    """Ingest CVE data from NVD."""

    def __init__(self, db_path: str = "kali_tools.db"):
        super().__init__(db_path)
        self.source_name = "NVD"
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch(self) -> None:
        """Fetch recent CVEs from NVD API."""
        try:
            # NVD API requires pagination
            # For now, fetch a small recent sample
            params = {
                "resultsPerPage": 20,
                "startIndex": 0,
                "sortBy": "published",
                "orderBy": "desc",
            }

            response = requests.get(self.api_url, params=params, timeout=10)
            response.raise_for_status()

            data = response.json()
            self.data = data.get("vulnerabilities", [])

            print(f"  Fetched {len(self.data)} CVEs from NVD")

        except Exception as e:
            print(f"  Error fetching from NVD: {e}")
            self.data = []

    def parse(self) -> None:
        """Parse NVD CVE data."""
        parsed = []

        for vuln in self.data:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            description = cve.get("descriptions", [{}])[0].get("value", "")
            severity = "unknown"

            # Try to extract CVSS score
            metrics = cve.get("metrics", {})
            if metrics.get("cvssV3_1"):
                severity_val = metrics["cvssV3_1"][0].get("cvssData", {}).get("baseSeverity")
                if severity_val:
                    severity = severity_val.lower()

            parsed.append({
                "cve_id": cve_id,
                "description": description[:200],
                "severity": severity,
                "source": "NVD",
            })

        self.data = parsed

    def store(self) -> None:
        """Store CVE data (stub - real implementation would update DB schema)."""
        # For now, just count. Real implementation would:
        # 1. Create cves table if needed
        # 2. Insert CVE records
        # 3. Link to affected tools
        for cve in self.data:
            print(f"  {cve['cve_id']}: {cve['severity']}")

    def run(self) -> Dict[str, Any]:
        """Execute ingester."""
        result = super().run()
        self.log_summary()
        return result
