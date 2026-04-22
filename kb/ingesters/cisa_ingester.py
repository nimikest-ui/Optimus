"""CISA KEV (Known Exploited Vulnerabilities) ingester."""

import requests
import json
from typing import Dict, List, Any
from kb.ingesters.base_ingester import BaseIngester


class CISAIngester(BaseIngester):
    """Ingest known exploited vulnerabilities from CISA."""

    def __init__(self, db_path: str = "kali_tools.db"):
        super().__init__(db_path)
        self.source_name = "CISA-KEV"
        self.api_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def fetch(self) -> None:
        """Fetch CISA KEV catalog."""
        try:
            response = requests.get(self.api_url, timeout=10)
            response.raise_for_status()

            data = response.json()
            self.data = data.get("vulnerabilities", [])

            print(f"  Fetched {len(self.data)} known exploited vulnerabilities from CISA")

        except Exception as e:
            print(f"  Error fetching from CISA: {e}")
            self.data = []

    def parse(self) -> None:
        """Parse CISA KEV data."""
        parsed = []

        for vuln in self.data:
            cve_id = vuln.get("cveID")
            product = vuln.get("product", "")
            vendor = vuln.get("vendor", "")
            due_date = vuln.get("dueDate", "")

            parsed.append({
                "cve_id": cve_id,
                "product": product,
                "vendor": vendor,
                "due_date": due_date,
                "source": "CISA-KEV",
                "actively_exploited": True,
            })

        self.data = parsed

    def store(self) -> None:
        """Store KEV data."""
        # Real implementation would link to affected products/tools
        for kev in self.data[:10]:  # Just show first 10
            print(f"  {kev['cve_id']}: {kev['vendor']} {kev['product']} (active)")

    def run(self) -> Dict[str, Any]:
        """Execute ingester."""
        result = super().run()
        self.log_summary()
        return result
