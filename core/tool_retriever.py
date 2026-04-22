"""Tool retrieval from kali_tools.db via FTS5 + attack_phase filter."""

import sqlite3
import json
from typing import Optional
from pydantic import BaseModel


class Tool(BaseModel):
    """Tool context for planner."""

    name: str
    syntax_template: str
    one_liner: str
    tier: int
    attack_phase: str
    success_rate: float


class ToolRetriever:
    """Retrieves relevant tools from database via FTS5 + attack_phase filter."""

    # Map user intent to relevant MITRE attack phases
    INTENT_PHASE_MAP = {
        "reconnaissance": ["reconnaissance", "discovery"],
        "enumeration": ["discovery", "reconnaissance"],
        "exploitation": ["initial-access", "execution"],
        "privilege_escalation": ["privilege-escalation", "execution"],
        "credential_access": ["credential-access", "execution"],
        "persistence": ["persistence", "command-and-control"],
        "exfiltration": ["exfiltration", "command-and-control"],
        "defense_evasion": ["defense-evasion", "execution"],
    }

    def __init__(self, db_path: str = "kali_tools.db"):
        self.db_path = db_path
        self.token_budget = 800  # ~800 tokens max for tool context

    def _phases_for_intent(self, intent: str) -> list[str]:
        """Map user intent to relevant MITRE attack phases."""
        intent_normalized = intent.lower().replace(" ", "_")
        return self.INTENT_PHASE_MAP.get(intent_normalized, ["discovery", "reconnaissance"])

    def retrieve(
        self,
        query: str,
        attack_phase: Optional[str] = None,
        intent: Optional[str] = None,
        limit: int = 10,
    ) -> list[Tool]:
        """
        Retrieve tools matching query, optionally filtered by attack_phase or intent.

        Args:
            query: Search query (tool name, keyword, description)
            attack_phase: Specific MITRE ATT&CK phase to filter by (optional)
            intent: User intent to map to multiple phases (optional)
            limit: Max number of tools to return

        Returns:
            List of Tool objects, ranked by success_rate (highest first)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Determine which phases to search
        if attack_phase and attack_phase != "unknown":
            phases = [attack_phase]
        elif intent:
            phases = self._phases_for_intent(intent)
        else:
            phases = None

        # Build base query
        if phases:
            # Phase-filtered search (multiple phases)
            placeholders = ",".join("?" * len(phases))
            sql = f"""
                SELECT tool_name, syntax_template, one_line_desc,
                       tier, attack_phase, success_rate
                FROM kali_tools
                WHERE attack_phase IN ({placeholders}) AND (
                    tool_name LIKE ? OR
                    tags LIKE ? OR
                    one_line_desc LIKE ?
                )
                ORDER BY success_rate DESC, use_count DESC
                LIMIT ?
            """
            search_pattern = f"%{query}%"
            params = list(phases) + [search_pattern, search_pattern, search_pattern, limit]
            cursor.execute(sql, params)
        else:
            # Unrestricted search (all phases)
            sql = """
                SELECT tool_name, syntax_template, one_line_desc,
                       tier, attack_phase, success_rate
                FROM kali_tools
                WHERE tool_name LIKE ? OR tags LIKE ? OR one_line_desc LIKE ?
                ORDER BY success_rate DESC, use_count DESC
                LIMIT ?
            """
            search_pattern = f"%{query}%"
            cursor.execute(sql, (search_pattern, search_pattern, search_pattern, limit))

        tools = []
        for row in cursor.fetchall():
            tool_name, syntax, desc, tier, phase, rate = row
            tools.append(
                Tool(
                    name=tool_name,
                    syntax_template=syntax or f"{tool_name} [OPTIONS]",
                    one_liner=desc or f"Tool from Kali Linux",
                    tier=tier or 1,
                    attack_phase=phase or "unknown",
                    success_rate=rate or 0.5,
                )
            )

        conn.close()
        return tools

    def retrieve_by_phase(self, attack_phase: str, limit: int = 10) -> list[Tool]:
        """Retrieve top tools for a specific attack phase."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        sql = """
            SELECT tool_name, syntax_template, one_line_desc,
                   tier, attack_phase, success_rate
            FROM kali_tools
            WHERE attack_phase = ?
            ORDER BY success_rate DESC, use_count DESC
            LIMIT ?
        """

        cursor.execute(sql, (attack_phase, limit))

        tools = []
        for row in cursor.fetchall():
            tool_name, syntax, desc, tier, phase, rate = row
            tools.append(
                Tool(
                    name=tool_name,
                    syntax_template=syntax or f"{tool_name} [OPTIONS]",
                    one_liner=desc or f"Tool from Kali Linux",
                    tier=tier or 1,
                    attack_phase=phase or "unknown",
                    success_rate=rate or 0.5,
                )
            )

        conn.close()
        return tools

    def to_json_context(self, tools: list[Tool]) -> str:
        """Convert tools to compact JSON context (~800 tokens)."""
        context = [
            {
                "name": t.name,
                "syntax_template": t.syntax_template,
                "one_liner": t.one_liner,
                "tier": t.tier,
                "attack_phase": t.attack_phase,
                "success_rate": round(t.success_rate, 2),
            }
            for t in tools
        ]
        return json.dumps(context, indent=2)

    def list_phases(self) -> list[str]:
        """List all attack phases in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT DISTINCT attack_phase FROM kali_tools ORDER BY attack_phase")
        phases = [row[0] for row in cursor.fetchall()]

        conn.close()
        return phases

    def get_phase_summary(self) -> dict[str, int]:
        """Get count of tools per attack phase."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT attack_phase, COUNT(*) as count
            FROM kali_tools
            GROUP BY attack_phase
            ORDER BY count DESC
            """
        )

        summary = {row[0]: row[1] for row in cursor.fetchall()}

        conn.close()
        return summary
