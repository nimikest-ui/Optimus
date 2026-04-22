"""Parse tool output into structured JSON."""

import re
import csv
import json
import sqlite3
from typing import Optional, Dict, Any, List
from pathlib import Path
from pydantic import BaseModel
from core.executor import ExecutorResult


class ParserResult(BaseModel):
    """Result of output parsing."""

    tool_name: str
    success: bool
    data: Dict[str, Any]  # Structured output
    extracted_count: int  # Number of items extracted


class OutputParser:
    """Parse tool output based on metadata."""

    def __init__(self, db_path: str = "kali_tools.db"):
        self.db_path = db_path

    def parse(self, tool_name: str, executor_result: ExecutorResult) -> ParserResult:
        """
        Parse tool output into structured format.

        Args:
            tool_name: Tool that was executed
            executor_result: Output from executor

        Returns:
            ParserResult with structured data
        """
        # Get metadata to find parser type
        parser_type = self._get_parser_type(tool_name)

        # Dispatch to appropriate parser
        if parser_type == "nmap_xml":
            return self._parse_nmap_xml(tool_name, executor_result)
        elif parser_type == "csv_networks":
            return self._parse_csv_networks(tool_name, executor_result)
        elif parser_type == "aircrack_stdout":
            return self._parse_aircrack_stdout(tool_name, executor_result)
        elif parser_type == "cracker_stdout":
            return self._parse_cracker_stdout(tool_name, executor_result)
        elif parser_type == "plain_text":
            return self._parse_plain_text(tool_name, executor_result)
        else:
            # Default regex fallback
            return self._parse_regex_fallback(tool_name, executor_result)

    def _get_parser_type(self, tool_name: str) -> str:
        """Get parser type from metadata."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT parser_type FROM tool_metadata WHERE tool_name = ?",
                (tool_name,),
            )

            row = cursor.fetchone()
            conn.close()

            if row:
                return row[0] or "regex"

        except Exception:
            pass

        return "regex"

    def _parse_nmap_xml(self, tool_name: str, result: ExecutorResult) -> ParserResult:
        """Parse nmap XML output."""
        # Simple text-based extraction (not full XML parsing)
        data = {
            "hosts": [],
            "ports": [],
            "services": [],
        }

        # Extract hosts
        for match in re.finditer(r"<host.*?starttime.*?endtime", result.stdout):
            data["hosts"].append(match.group(0)[:50])

        # Extract ports
        for match in re.finditer(r"<port.*?state.*?service", result.stdout):
            data["ports"].append(match.group(0)[:50])

        # Extract services
        for match in re.finditer(r"service name=['\"]([^'\"]+)['\"]", result.stdout):
            data["services"].append(match.group(1))

        return ParserResult(
            tool_name=tool_name,
            success=result.exit_code == 0,
            data=data,
            extracted_count=len(data["hosts"]),
        )

    def _parse_csv_networks(self, tool_name: str, result: ExecutorResult) -> ParserResult:
        """Parse CSV output (airodump-ng networks)."""
        data = {"networks": []}

        # Read CSV file
        if result.output_files:
            csv_file = result.output_files[0]
            try:
                with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row and any(row.values()):  # Skip empty rows
                            # Try multiple field name variations
                            network = {
                                "bssid": (row.get("BSSID") or row.get("bssid") or "").strip(),
                                "ssid": (row.get("SSID") or row.get("ssid") or "").strip(),
                                "channel": (row.get("Channel") or row.get("CH") or row.get("channel") or "").strip(),
                                "power": (row.get("Power") or row.get("PWR") or row.get("power") or "").strip(),
                                "beacons": (row.get("Beacons") or row.get("beacons") or "").strip(),
                                "privacy": (row.get("Privacy") or row.get("privacy") or "").strip(),
                            }
                            if network["bssid"]:  # Only if BSSID exists
                                data["networks"].append(network)
            except Exception as e:
                return ParserResult(
                    tool_name=tool_name,
                    success=False,
                    data={"error": str(e)},
                    extracted_count=0,
                )

        return ParserResult(
            tool_name=tool_name,
            success=len(data["networks"]) > 0,
            data=data,
            extracted_count=len(data["networks"]),
        )

    def _parse_aircrack_stdout(self, tool_name: str, result: ExecutorResult) -> ParserResult:
        """Parse aircrack-ng output."""
        data = {
            "password_found": False,
            "key": None,
            "progress": None,
        }

        # Look for key found pattern
        key_match = re.search(r"Key found!\s*\[\s*([^\]]+)\s*\]", result.stdout)
        if key_match:
            data["password_found"] = True
            data["key"] = key_match.group(1).strip()

        # Look for progress
        progress_match = re.search(r"\[(\d+)%\]", result.stdout)
        if progress_match:
            data["progress"] = int(progress_match.group(1))

        return ParserResult(
            tool_name=tool_name,
            success=data["password_found"],
            data=data,
            extracted_count=1 if data["password_found"] else 0,
        )

    def _parse_cracker_stdout(self, tool_name: str, result: ExecutorResult) -> ParserResult:
        """Parse password cracker output (hashcat, john)."""
        data = {
            "password_found": False,
            "passwords": [],
            "progress": None,
        }

        # Look for common password found patterns
        patterns = [
            r"password[:\s]+([^\n]+)",
            r"recovered[:\s]+([^\n]+)",
            r"found[:\s]+([^\n]+)",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, result.stdout, re.IGNORECASE):
                password = match.group(1).strip()
                if password and password not in data["passwords"]:
                    data["passwords"].append(password)
                    data["password_found"] = True

        # Look for progress
        progress_match = re.search(r"(\d+)%", result.stdout)
        if progress_match:
            data["progress"] = int(progress_match.group(1))

        return ParserResult(
            tool_name=tool_name,
            success=data["password_found"],
            data=data,
            extracted_count=len(data["passwords"]),
        )

    def _parse_plain_text(self, tool_name: str, result: ExecutorResult) -> ParserResult:
        """Parse plain text output (gobuster, etc)."""
        data = {"lines": [], "found": []}

        for line in result.stdout.split("\n"):
            line = line.strip()
            if line:
                data["lines"].append(line)
                # Try to identify "found" results
                if any(x in line.lower() for x in ["status", "found", "200", "302"]):
                    data["found"].append(line)

        return ParserResult(
            tool_name=tool_name,
            success=result.exit_code == 0,
            data=data,
            extracted_count=len(data["found"]),
        )

    def _parse_regex_fallback(self, tool_name: str, result: ExecutorResult) -> ParserResult:
        """Fallback regex extraction for unknown tools."""
        data = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "cves": [],
        }

        # Extract IPs
        ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        data["ips"] = list(set(re.findall(ip_pattern, result.stdout)))

        # Extract domains
        domain_pattern = r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"
        data["domains"] = list(set(re.findall(domain_pattern, result.stdout.lower())))

        # Extract URLs
        url_pattern = r"https?://[^\s]+"
        data["urls"] = list(set(re.findall(url_pattern, result.stdout)))

        # Extract hashes (MD5, SHA1, SHA256)
        hash_pattern = r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b"
        data["hashes"] = list(set(re.findall(hash_pattern, result.stdout.lower())))

        # Extract CVEs
        cve_pattern = r"CVE-\d{4}-\d{4,}"
        data["cves"] = list(set(re.findall(cve_pattern, result.stdout, re.IGNORECASE)))

        extracted_count = sum(len(v) for k, v in data.items() if isinstance(v, list))

        return ParserResult(
            tool_name=tool_name,
            success=extracted_count > 0 and result.exit_code == 0,
            data=data,
            extracted_count=extracted_count,
        )
