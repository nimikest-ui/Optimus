"""Self-improvement: Save successful runs as new playbooks, update EWMA scores."""

import sqlite3
import yaml
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from core.session import Session
from core.planner import ExecutionStep


class Reflector:
    """Learns from successful runs and improves tool scores."""

    def __init__(self, db_path: str = "kali_tools.db", playbook_dir: str = "artifacts/playbooks"):
        self.db_path = db_path
        self.playbook_dir = Path(playbook_dir)
        self.playbook_dir.mkdir(parents=True, exist_ok=True)

    def reflect_on_success(
        self,
        session_id: int,
        project_id: str,
        target: str,
        steps: List[ExecutionStep],
    ) -> None:
        """
        After successful session, learn from it:
        1. Create playbook YAML from steps
        2. Save as new recipe
        3. Update EWMA scores for tools used
        """
        print(f"\n[REFLECT] Learning from successful session {session_id}")

        # Create and save playbook
        playbook = self._build_playbook_yaml(project_id, target, steps)
        playbook_path = self._save_playbook(playbook, target)
        print(f"  ✓ Saved playbook: {playbook_path}")

        # Update EWMA scores
        updated_tools = self._update_ewma_scores(steps, success=True)
        print(f"  ✓ Updated EWMA for {len(updated_tools)} tools")

        # Increment use_count
        self._increment_use_count(steps)
        print(f"  ✓ Incremented use_count")

    def reflect_on_failure(
        self,
        steps: List[ExecutionStep],
    ) -> None:
        """After failed session, update EWMA scores (negative)."""
        print(f"\n[REFLECT] Learning from failed session")

        updated_tools = self._update_ewma_scores(steps, success=False)
        print(f"  ✓ Updated EWMA for {len(updated_tools)} tools (penalty)")

    def _build_playbook_yaml(
        self, project_id: str, target: str, steps: List[ExecutionStep]
    ) -> Dict[str, Any]:
        """Build YAML playbook from successful steps."""
        playbook = {
            "name": f"{project_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "description": f"Auto-generated playbook for {target}",
            "target": target,
            "created": datetime.now().isoformat(),
            "steps": [],
        }

        for step in steps:
            playbook["steps"].append({
                "step": step.step_num,
                "goal": step.goal,
                "tool": step.tool,
                "args": step.args,
                "success_criteria": step.success_criteria,
                "timeout": step.timeout,
            })

        return playbook

    def _save_playbook(self, playbook: Dict[str, Any], target: str) -> Path:
        """Save playbook YAML to disk."""
        # Create filename from target
        target_safe = target.replace("/", "_").replace(":", "_")[:30]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target_safe}_{timestamp}.yaml"

        filepath = self.playbook_dir / filename

        with open(filepath, "w") as f:
            yaml.dump(playbook, f, default_flow_style=False)

        return filepath

    def _update_ewma_scores(self, steps: List[ExecutionStep], success: bool) -> List[str]:
        """
        Update EWMA (exponential weighted moving average) scores.

        Success: success_rate += (1 - success_rate) * 0.1
        Failure: success_rate -= success_rate * 0.1
        """
        updated_tools = []

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for step in steps:
                tool_name = step.tool

                # Get current score
                cursor.execute(
                    "SELECT success_rate FROM kali_tools WHERE tool_name = ?",
                    (tool_name,),
                )
                row = cursor.fetchone()
                if not row:
                    continue

                current_rate = row[0] or 0.5

                # Update based on success/failure
                if success:
                    # Success: move toward 1.0
                    new_rate = current_rate + (1 - current_rate) * 0.1
                else:
                    # Failure: move toward 0.0
                    new_rate = current_rate - current_rate * 0.1

                # Clamp to [0, 1]
                new_rate = max(0.0, min(1.0, new_rate))

                # Update database
                cursor.execute(
                    "UPDATE kali_tools SET success_rate = ? WHERE tool_name = ?",
                    (new_rate, tool_name),
                )

                updated_tools.append(tool_name)
                print(f"    {tool_name}: {current_rate:.2f} → {new_rate:.2f}")

            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Error updating EWMA: {e}")

        return updated_tools

    def _increment_use_count(self, steps: List[ExecutionStep]) -> None:
        """Increment use_count for all tools used."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for step in steps:
                cursor.execute(
                    "UPDATE kali_tools SET use_count = use_count + 1 WHERE tool_name = ?",
                    (step.tool,),
                )

            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Error incrementing use_count: {e}")


def reflect_success(
    session_id: int,
    project_id: str,
    target: str,
    steps: List[ExecutionStep],
    db_path: str = "kali_tools.db",
) -> None:
    """Convenience function for success reflection."""
    reflector = Reflector(db_path)
    reflector.reflect_on_success(session_id, project_id, target, steps)


def reflect_failure(
    steps: List[ExecutionStep],
    db_path: str = "kali_tools.db",
) -> None:
    """Convenience function for failure reflection."""
    reflector = Reflector(db_path)
    reflector.reflect_on_failure(steps)
