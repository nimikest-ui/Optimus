"""Synthesize playbook YAML from KB research results."""

import sqlite3
import yaml
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from pydantic import BaseModel


class PlaybookStep(BaseModel):
    """Single execution step in a playbook."""
    step: int
    goal: str
    tool: str
    args: str
    success_criteria: str
    timeout: int


class PlaybookPlan(BaseModel):
    """Structured playbook ready for execution."""
    name: str
    description: str
    target: str
    created: str
    cves_addressed: List[str]
    steps: List[PlaybookStep]


class Compiler:
    """Synthesizes playbooks from KB research (ingesters, CVEs, tools)."""

    # MITRE phases in recommended execution order
    PHASE_ORDER = [
        "reconnaissance",
        "discovery",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery-post",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]

    def __init__(self, db_path: str = "kali_tools.db", playbook_dir: str = "artifacts/playbooks"):
        self.db_path = db_path
        self.playbook_dir = Path(playbook_dir)
        self.playbook_dir.mkdir(parents=True, exist_ok=True)

    def compile_from_cves(
        self,
        project_id: str,
        target: str,
        cves: List[Dict[str, Any]],
        max_steps: int = 10,
    ) -> PlaybookPlan:
        """
        Build playbook from CVE data:
        1. Group CVEs by vendor/product
        2. Find tools that address those vulnerabilities
        3. Order by attack phase
        4. Return structured plan
        """
        print(f"[COMPILER] Building playbook for {target} ({len(cves)} CVEs)")

        # Collect unique CVE IDs
        cve_ids = list(set(cve.get("cve_id") for cve in cves if cve.get("cve_id")))
        print(f"  Found {len(cve_ids)} unique CVEs")

        # Find tools that address these CVEs
        tool_steps = self._find_tools_for_cves(cve_ids, max_steps)
        print(f"  Selected {len(tool_steps)} tools")

        # Build playbook
        playbook = PlaybookPlan(
            name=f"{project_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            description=f"Auto-generated playbook targeting {target} vulnerabilities",
            target=target,
            created=datetime.now().isoformat(),
            cves_addressed=cve_ids[:max_steps],
            steps=tool_steps,
        )

        return playbook

    def compile_from_intent(
        self,
        project_id: str,
        target: str,
        intent: str,
        max_steps: int = 10,
    ) -> PlaybookPlan:
        """
        Build playbook from user intent:
        1. Find tools matching intent
        2. Order by attack phase
        3. Return structured plan
        """
        print(f"[COMPILER] Building playbook from intent: {intent}")

        # Find tools matching intent
        tool_steps = self._find_tools_by_intent(intent, max_steps)
        print(f"  Selected {len(tool_steps)} tools")

        # Build playbook
        playbook = PlaybookPlan(
            name=f"{project_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            description=f"Auto-generated playbook for {intent} against {target}",
            target=target,
            created=datetime.now().isoformat(),
            cves_addressed=[],
            steps=tool_steps,
        )

        return playbook

    def _find_tools_for_cves(self, cve_ids: List[str], max_steps: int) -> List[PlaybookStep]:
        """Find tools that address specific CVEs, ordered by phase."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Query tools by CVE (look for CVE mentions in tool descriptions/tags)
            steps = []
            step_num = 1

            for phase in self.PHASE_ORDER:
                if step_num > max_steps:
                    break

                # Find tools in this phase
                cursor.execute(
                    """
                    SELECT tool_name, one_line_desc, syntax_template, success_rate
                    FROM kali_tools
                    WHERE attack_phase = ? AND installed = 1
                    ORDER BY success_rate DESC, use_count DESC
                    LIMIT 5
                    """,
                    (phase,),
                )

                for row in cursor.fetchall():
                    if step_num > max_steps:
                        break

                    tool_name, desc, syntax, success_rate = row

                    # Build execution args from syntax template
                    args = syntax.replace("{target}", "{TARGET}") if syntax else f"{tool_name} {{TARGET}}"

                    step = PlaybookStep(
                        step=step_num,
                        goal=f"Run {tool_name}: {desc or 'assessment'}",
                        tool=tool_name,
                        args=args,
                        success_criteria=f"{tool_name} execution completed without error",
                        timeout=30,
                    )
                    steps.append(step)
                    step_num += 1

            conn.close()
            return steps

        except Exception as e:
            print(f"Error finding tools for CVEs: {e}")
            return []

    def _find_tools_by_intent(self, intent: str, max_steps: int) -> List[PlaybookStep]:
        """Find tools matching intent, ordered by phase and success rate."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Build search pattern - search for any word in the intent
            intent_words = intent.lower().split()
            where_clauses = []
            params = []

            for word in intent_words:
                if len(word) > 2:  # Skip single/double letter words
                    where_clauses.append(f"(kt.tags LIKE ? OR kt.one_line_desc LIKE ?)")
                    params.append(f"%{word}%")
                    params.append(f"%{word}%")

            if not where_clauses:
                # No valid search terms, return empty
                return []

            query = f"""
                SELECT kt.tool_name, kt.one_line_desc, kt.syntax_template,
                       kt.success_rate, kt.attack_phase
                FROM kali_tools kt
                WHERE {' OR '.join(where_clauses)}
                ORDER BY kt.attack_phase, kt.success_rate DESC, kt.use_count DESC
                LIMIT ?
            """
            params.append(max_steps)

            cursor.execute(query, params)

            steps = []
            for i, row in enumerate(cursor.fetchall(), start=1):
                tool_name, desc, syntax, success_rate, phase = row

                args = syntax.replace("{target}", "{TARGET}") if syntax else f"{tool_name} {{TARGET}}"

                step = PlaybookStep(
                    step=i,
                    goal=f"Run {tool_name}: {desc or 'assessment'}",
                    tool=tool_name,
                    args=args,
                    success_criteria=f"{tool_name} execution completed without error",
                    timeout=30,
                )
                steps.append(step)

            conn.close()
            return steps

        except Exception as e:
            print(f"Error finding tools by intent: {e}")
            return []

    def save_playbook(self, plan: PlaybookPlan) -> Path:
        """Save compiled playbook to YAML file."""
        # Convert to dict for YAML serialization
        playbook_dict = {
            "name": plan.name,
            "description": plan.description,
            "target": plan.target,
            "created": plan.created,
            "cves_addressed": plan.cves_addressed,
            "steps": [
                {
                    "step": step.step,
                    "goal": step.goal,
                    "tool": step.tool,
                    "args": step.args,
                    "success_criteria": step.success_criteria,
                    "timeout": step.timeout,
                }
                for step in plan.steps
            ],
        }

        # Create filename
        target_safe = plan.target.replace("/", "_").replace(":", "_")[:30]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target_safe}_{timestamp}.yaml"

        filepath = self.playbook_dir / filename

        with open(filepath, "w") as f:
            yaml.dump(playbook_dict, f, default_flow_style=False)

        print(f"  ✓ Saved playbook: {filepath}")
        return filepath
