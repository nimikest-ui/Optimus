"""Deep research: combine online searches + local KB."""

import sqlite3
import json
import re
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass


@dataclass
class ResearchFinding:
    """Single research finding."""
    query: str
    source: str  # google, github, exploit-db, etc.
    title: str
    url: str
    summary: str
    cves: List[str]
    tools: List[str]
    severity: Optional[str] = None


class Researcher:
    """Performs deep research and stores findings."""

    def __init__(self, db_path: str = "kali_tools.db"):
        self.db_path = db_path

    def research(self, query: str, sources: Optional[List[str]] = None) -> List[ResearchFinding]:
        """
        Perform deep research on a topic.

        Args:
            query: Research topic (e.g., "airmon-ng", "Apache CVE")
            sources: List of sources to search (google, github, exploit-db, etc.)

        Returns:
            List of research findings
        """
        if sources is None:
            sources = ["google", "github", "exploit-db"]

        findings = []

        for source in sources:
            print(f"[RESEARCH] Searching {source} for '{query}'...")
            try:
                if source == "google":
                    findings.extend(self._search_google(query))
                elif source == "github":
                    findings.extend(self._search_github(query))
                elif source == "exploit-db":
                    findings.extend(self._search_exploit_db(query))
                elif source == "threat-feeds":
                    findings.extend(self._search_threat_feeds(query))
            except Exception as e:
                print(f"  Error searching {source}: {e}")

        # Store findings in DB
        self._store_findings(query, findings)

        return findings

    def _search_google(self, query: str) -> List[ResearchFinding]:
        """Search Google for vulnerabilities and exploits."""
        try:
            from web import WebSearch
        except ImportError:
            # Fallback: simulate search results for demo
            print("  (WebSearch not available, using simulated results)")
            return self._simulate_google_results(query)

        findings = []
        search_query = f"{query} vulnerability exploit CVE 2025 2026"

        try:
            # This would use the WebSearch tool (if available)
            results = WebSearch(search_query).results()

            for i, result in enumerate(results[:5]):  # Top 5 results
                cves = self._extract_cves(result.get("description", ""))
                tools = self._extract_tools(result.get("description", ""))

                finding = ResearchFinding(
                    query=query,
                    source="google",
                    title=result.get("title", ""),
                    url=result.get("url", ""),
                    summary=result.get("description", "")[:500],
                    cves=cves,
                    tools=tools,
                    severity=self._infer_severity(result.get("description", "")),
                )
                findings.append(finding)

        except Exception as e:
            print(f"    Google search error: {e}")

        return findings

    def _search_github(self, query: str) -> List[ResearchFinding]:
        """Search GitHub for POCs and tool repos."""
        findings = []

        # Simulate GitHub search results
        # In real implementation, would use GitHub API
        simulated_results = [
            {
                "title": f"{query} - Proof of Concept",
                "url": f"https://github.com/search?q={query}+poc",
                "description": f"POC for {query} vulnerability. Working exploit code.",
                "severity": "high",
            },
            {
                "title": f"{query} - Security Assessment",
                "url": f"https://github.com/search?q={query}+security",
                "description": f"Security assessment tools for {query}",
                "severity": "medium",
            },
        ]

        for result in simulated_results:
            cves = self._extract_cves(result["description"])
            tools = self._extract_tools(result["description"])

            finding = ResearchFinding(
                query=query,
                source="github",
                title=result["title"],
                url=result["url"],
                summary=result["description"],
                cves=cves,
                tools=tools,
                severity=result.get("severity"),
            )
            findings.append(finding)

        return findings

    def _search_exploit_db(self, query: str) -> List[ResearchFinding]:
        """Search Exploit-DB for known exploits."""
        findings = []

        # Simulate Exploit-DB results
        # In real implementation, would query Exploit-DB API
        simulated_results = [
            {
                "title": f"{query} - Remote Code Execution",
                "url": f"https://www.exploit-db.com/search?q={query}",
                "description": f"Exploit for {query} RCE vulnerability",
                "severity": "critical",
                "cves": ["CVE-2025-12345"],
            },
            {
                "title": f"{query} - Privilege Escalation",
                "url": f"https://www.exploit-db.com/search?q={query}+privesc",
                "description": f"Privilege escalation in {query}",
                "severity": "high",
                "cves": ["CVE-2025-54321"],
            },
        ]

        for result in simulated_results:
            cves = result.get("cves", self._extract_cves(result["description"]))
            tools = self._extract_tools(result["description"])

            finding = ResearchFinding(
                query=query,
                source="exploit-db",
                title=result["title"],
                url=result["url"],
                summary=result["description"],
                cves=cves,
                tools=tools,
                severity=result.get("severity"),
            )
            findings.append(finding)

        return findings

    def _search_threat_feeds(self, query: str) -> List[ResearchFinding]:
        """Search threat intelligence feeds."""
        findings = []

        # Simulate threat feed results
        simulated_results = [
            {
                "title": f"{query} - Active Exploitation Reported",
                "url": "https://example.com/threat-feed",
                "description": f"{query} is being actively exploited in the wild",
                "severity": "critical",
            },
        ]

        for result in simulated_results:
            cves = self._extract_cves(result["description"])
            tools = self._extract_tools(result["description"])

            finding = ResearchFinding(
                query=query,
                source="threat-feeds",
                title=result["title"],
                url=result["url"],
                summary=result["description"],
                cves=cves,
                tools=tools,
                severity=result.get("severity"),
            )
            findings.append(finding)

        return findings

    def _simulate_google_results(self, query: str) -> List[ResearchFinding]:
        """Fallback: simulate Google results for demo."""
        return [
            ResearchFinding(
                query=query,
                source="google",
                title=f"{query} Security Vulnerabilities",
                url=f"https://google.com/search?q={query}+vulnerability",
                summary=f"Information about {query} security issues and CVEs",
                cves=self._extract_cves(query),
                tools=[],
                severity="medium",
            ),
        ]

    def _extract_cves(self, text: str) -> List[str]:
        """Extract CVE IDs from text."""
        pattern = r"CVE-\d{4}-\d{4,5}"
        return list(set(re.findall(pattern, text, re.IGNORECASE)))

    def _extract_tools(self, text: str) -> List[str]:
        """Extract tool names from text."""
        # Common security tools
        tools = [
            "nikto", "nmap", "metasploit", "burp", "zaproxy",
            "sqlmap", "hashcat", "john", "aircrack", "airmon",
            "wfuzz", "gobuster", "dirb", "ffuf", "searchsploit",
        ]

        found_tools = []
        text_lower = text.lower()
        for tool in tools:
            if tool in text_lower:
                found_tools.append(tool)

        return found_tools

    def _infer_severity(self, text: str) -> Optional[str]:
        """Infer severity from text."""
        text_lower = text.lower()
        if any(word in text_lower for word in ["critical", "rce", "remote code"]):
            return "critical"
        elif any(word in text_lower for word in ["high", "exploit", "active"]):
            return "high"
        elif any(word in text_lower for word in ["medium", "vulnerability"]):
            return "medium"
        return None

    def _store_findings(self, query: str, findings: List[ResearchFinding]) -> None:
        """Store research findings in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for finding in findings:
            cves_json = json.dumps(finding.cves)
            tools_json = json.dumps(finding.tools)

            cursor.execute(
                """
                INSERT INTO research_findings
                (query, source, title, url, summary, cves, tools, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.query,
                    finding.source,
                    finding.title,
                    finding.url,
                    finding.summary,
                    cves_json,
                    tools_json,
                    finding.severity,
                ),
            )

        conn.commit()
        conn.close()

        print(f"  ✓ Stored {len(findings)} findings")

    def query_research(self, query: str) -> List[Dict[str, Any]]:
        """Query stored research findings."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Extract keywords from query (split by spaces, filter short ones, remove special chars)
        keywords = [
            kw.replace("'", "").replace('"', '')
            for kw in query.lower().split()
            if len(kw) > 2
        ]

        # Build parameterized query
        if keywords:
            where_conditions = [f"query LIKE ?" for _ in keywords]
            where_clause = " OR ".join(where_conditions)
            params = [f"%{kw}%" for kw in keywords]
        else:
            where_clause = "1=1"
            params = []

        query_str = f"""
            SELECT query, source, title, url, summary, cves, tools, severity, found_at
            FROM research_findings
            WHERE {where_clause}
            ORDER BY severity DESC, found_at DESC
        """

        cursor.execute(query_str, params)

        results = []
        for row in cursor.fetchall():
            results.append({
                "query": row[0],
                "source": row[1],
                "title": row[2],
                "url": row[3],
                "summary": row[4],
                "cves": json.loads(row[5]) if row[5] else [],
                "tools": json.loads(row[6]) if row[6] else [],
                "severity": row[7],
                "found_at": row[8],
            })

        conn.close()
        return results

    def get_cves_for_query(self, query: str) -> List[str]:
        """Get all CVEs mentioned in research for a query."""
        findings = self.query_research(query)
        all_cves = []
        for finding in findings:
            all_cves.extend(finding["cves"])
        return list(set(all_cves))

    def get_tools_for_query(self, query: str) -> List[str]:
        """Get all tools mentioned in research for a query."""
        findings = self.query_research(query)
        all_tools = []
        for finding in findings:
            all_tools.extend(finding["tools"])
        return list(set(all_tools))
