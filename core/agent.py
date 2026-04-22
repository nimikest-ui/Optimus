"""Intelligent agent: uses research data + reflector scores to execute missions."""

import sqlite3
import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from core.prompt_analyzer import PromptAnalyzer
from core.tool_retriever import ToolRetriever
from core.executor import Executor
from core.output_parser import OutputParser
from core.session import Session
from core.reflect import Reflector
from kb.researcher import Researcher
from kb.compiler import PlaybookStep


class AgentPlan(BaseModel):
    """Agent execution plan informed by research + reflector."""
    mission: str
    target: str
    research_query: str
    found_cves: List[str]
    research_tools: List[str]
    selected_tools: List[PlaybookStep]
    reasoning: str


class IntelligentAgent:
    """Agent that uses research + reflector scores to select tools."""

    def __init__(self, db_path: str = "kali_tools.db", project_id: str = "auto"):
        self.db_path = db_path
        self.project_id = project_id
        self.analyzer = PromptAnalyzer()
        self.retriever = ToolRetriever(db_path)
        self.executor = Executor(db_path)
        self.parser = OutputParser()
        self.reflector = Reflector(db_path)
        self.researcher = Researcher(db_path)

    def execute_mission(
        self,
        mission: str,
        target: str,
        tier: int = 1,
    ) -> Dict[str, Any]:
        """
        Execute a mission using intelligent tool selection.

        Args:
            mission: What to do (e.g., "find Apache vulnerabilities")
            target: Target IP/domain
            tier: Execution tier (1=passive, 2=active, 3=destructive)

        Returns:
            Result dict with findings, execution log, etc.
        """
        print(f"\n[AGENT] Mission: {mission}")
        print(f"[AGENT] Target: {target}")
        print(f"[AGENT] Tier: {tier}")

        # STEP 1: Analyze mission
        print(f"\n[AGENT] Step 1: Analyzing mission...")
        analysis = self.analyzer.analyze(mission)
        intent = analysis.intent
        domain = analysis.domain
        print(f"  Intent: {intent}")
        print(f"  Domain: {domain}")

        # STEP 2: Query research findings
        print(f"\n[AGENT] Step 2: Querying research database...")
        # Use mission text directly for research lookup (contains specific products/services)
        cves = self.researcher.get_cves_for_query(mission)
        research_tools = self.researcher.get_tools_for_query(mission)
        print(f"  Found {len(cves)} CVEs in research: {cves[:5]}")
        print(f"  Found {len(research_tools)} tools mentioned: {research_tools}")

        # STEP 3: Select tools using research + reflector
        print(f"\n[AGENT] Step 3: Selecting tools (research + EWMA scores)...")
        selected_tools = self._select_tools(
            intent=intent,
            domain=domain,
            cves=cves,
            research_tools=research_tools,
            tier=tier,
        )
        print(f"  Selected {len(selected_tools)} tools")

        # Check if any tools were selected
        if not selected_tools:
            print(f"  ✗ No tools matched for intent '{intent}' and tier {tier}")
            return {
                "session_id": None,
                "mission": mission,
                "target": target,
                "cves_found": cves,
                "tools_used": [],
                "execution_results": [],
                "outcome": "no_tools_available",
            }

        # STEP 4: Create session
        print(f"\n[AGENT] Step 4: Creating execution session...")
        session = Session(
            project_id=self.project_id,
            playbook=f"auto-{intent}",
            target=target,
            tier=tier,
            token_budget=4000,
            db_path=self.db_path,
        )
        print(f"  Session ID: {session.session_id}")

        # STEP 5: Execute tools
        print(f"\n[AGENT] Step 5: Executing tools...")
        execution_results = []
        all_success = True

        for step in selected_tools:
            print(f"\n  [STEP {step.step}] {step.goal}")
            print(f"    Tool: {step.tool}")

            # Replace target placeholder (handle flexible targets)
            # If target is descriptive (not IP/domain), some tools may need adjustment
            if target.lower() in ["local", "localhost", "127.0.0.1", "nearby", "around", "local network"]:
                # For local scanning, use 127.0.0.1 or localhost as default
                target_for_tool = "127.0.0.1"
            else:
                target_for_tool = target

            args_list = step.args.replace("{TARGET}", target_for_tool).split()

            # Execute
            result = self.executor.execute(
                tool_name=step.tool,
                args=args_list,
                timeout=step.timeout,
            )

            # Parse output
            try:
                parsed = self.parser.parse(step.tool, result)
                parsed_str = json.dumps(parsed.dict())
            except Exception as e:
                parsed_str = result.stdout[:500]

            # Record step
            session.add_step(
                step_num=step.step,
                goal=step.goal,
                tool_used=step.tool,
                args=step.args,
                outcome="success" if result.exit_code == 0 else "fail",
                raw_output=result.stdout,
                parsed_output=parsed_str,
                attempt_count=1,
            )

            execution_results.append({
                "step": step.step,
                "tool": step.tool,
                "success": result.exit_code == 0,
                "output": result.stdout[:200],
            })

            if result.exit_code == 0:
                print(f"    ✓ Success")
            else:
                print(f"    ✗ Failed: {result.stderr}")
                all_success = False

        # STEP 6: Reflect
        print(f"\n[AGENT] Step 6: Learning from execution...")
        session.finish(outcome="success" if all_success else "partial")

        if all_success and selected_tools:
            from core.planner import ExecutionStep
            steps = [
                ExecutionStep(
                    step_num=t.step,
                    goal=t.goal,
                    tool=t.tool,
                    args=t.args,
                    success_criteria=t.success_criteria,
                    timeout=t.timeout,
                )
                for t in selected_tools
            ]
            self.reflector.reflect_on_success(
                session_id=session.session_id,
                project_id=self.project_id,
                target=target,
                steps=steps,
            )
            print("  ✓ Updated EWMA scores")
        else:
            self.reflector.reflect_on_failure(selected_tools)
            print("  ✓ Reflected on failure")

        return {
            "session_id": session.session_id,
            "mission": mission,
            "target": target,
            "cves_found": cves,
            "tools_used": [t.tool for t in selected_tools],
            "execution_results": execution_results,
            "outcome": "success" if all_success else "partial",
        }

    def _select_tools(
        self,
        intent: str,
        domain: Optional[str],
        cves: List[str],
        research_tools: List[str],
        tier: int,
    ) -> List[PlaybookStep]:
        """
        Select tools using research findings + reflector scores.

        Priority:
        1. Tools mentioned in research + high EWMA score
        2. Tools for finding vulnerabilities (reconnaissance/enumeration tools)
        3. Top-ranked tools by EWMA score
        """
        # Query tools with EWMA scores
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        results = []

        # PRIORITY 1: Use research-identified tools first (if any found)
        if research_tools:
            placeholders = ','.join(['?' for _ in research_tools])
            query = f"""
                SELECT tool_name, one_line_desc, syntax_template, success_rate, attack_phase
                FROM kali_tools
                WHERE tool_name IN ({placeholders})
                AND (tier IS NULL OR tier <= ?)
                ORDER BY success_rate DESC, use_count DESC
                LIMIT 5
            """
            params = research_tools + [tier]
            try:
                cursor.execute(query, params)
                results = cursor.fetchall()
            except Exception as e:
                print(f"  Warning: Research tool lookup failed: {e}")

        # PRIORITY 2: Fallback to reconnaissance/discovery phase tools
        if not results:
            query = """
                SELECT tool_name, one_line_desc, syntax_template, success_rate, attack_phase
                FROM kali_tools
                WHERE (
                    attack_phase IN ('reconnaissance', 'discovery', 'initial-access')
                    OR tags LIKE ?
                    OR one_line_desc LIKE ?
                )
                AND (tier IS NULL OR tier <= ?)
                ORDER BY success_rate DESC, use_count DESC
                LIMIT 5
            """
            search_term = f"%{intent}%"
            params = [search_term, search_term, tier]

            try:
                cursor.execute(query, params)
                results = cursor.fetchall()
            except Exception as e:
                print(f"  Error selecting tools: {e}")
                results = []

        conn.close()

        # Check if we found any tools
        if not results:
            print(f"  ✗ No tools found for research targets or intent: {intent}")
            return []

        # Build execution steps
        steps = []
        for i, (tool_name, desc, syntax, success_rate, phase) in enumerate(results, 1):
            args = syntax.replace("{target}", "{TARGET}") if syntax else f"{tool_name} {{TARGET}}"

            step = PlaybookStep(
                step=i,
                goal=f"Run {tool_name}: {desc or 'assessment'}",
                tool=tool_name,
                args=args,
                success_criteria=f"{tool_name} execution completed",
                timeout=30,
            )
            steps.append(step)

        return steps
