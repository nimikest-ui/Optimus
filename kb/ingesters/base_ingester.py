"""Base ingester class for all data sources."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
import sqlite3


class BaseIngester(ABC):
    """Base class for all ingesters."""

    def __init__(self, db_path: str = "kali_tools.db"):
        self.db_path = db_path
        self.source_name = self.__class__.__name__
        self.data = []

    @abstractmethod
    def fetch(self) -> None:
        """Fetch data from source (API, local DB, etc)."""
        pass

    @abstractmethod
    def parse(self) -> None:
        """Parse fetched data into structured format."""
        pass

    @abstractmethod
    def store(self) -> None:
        """Store parsed data in database."""
        pass

    def run(self) -> Dict[str, Any]:
        """Execute ingester pipeline: fetch → parse → store."""
        result = {
            "source": self.source_name,
            "status": "failed",
            "records_processed": 0,
            "records_stored": 0,
            "error": None,
        }

        try:
            print(f"[{self.source_name}] Fetching...")
            self.fetch()

            print(f"[{self.source_name}] Parsing...")
            self.parse()

            print(f"[{self.source_name}] Storing...")
            self.store()

            result["status"] = "success"
            result["records_processed"] = len(self.data)
            result["records_stored"] = len(self.data)

        except Exception as e:
            result["error"] = str(e)
            print(f"[{self.source_name}] Error: {e}")

        return result

    def _update_kali_tools_cve(self, tool_name: str, cve_id: str, severity: str) -> None:
        """Link a CVE to a tool in the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check if tool exists
            cursor.execute("SELECT id FROM kali_tools WHERE tool_name = ?", (tool_name,))
            if not cursor.fetchone():
                # Insert placeholder tool
                cursor.execute(
                    """
                    INSERT INTO kali_tools
                    (tool_name, one_line_desc, success_rate, installed)
                    VALUES (?, ?, 0.5, 0)
                    """,
                    (tool_name, f"Software: {tool_name}"),
                )

            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Error updating kali_tools: {e}")

    def log_summary(self) -> None:
        """Print summary of ingestion."""
        print(f"[{self.source_name}] Processed {len(self.data)} records")
