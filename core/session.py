"""Session state tracking and token budget management."""

import sqlite3
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class SessionState(BaseModel):
    """Current session state."""

    session_id: int
    project_id: str
    playbook: str
    target: str
    tier: int
    started_at: datetime
    token_budget: int
    token_used: int
    outcome: Optional[str] = None  # success, partial, stuck


class Step(BaseModel):
    """Execution step record."""

    session_id: int
    step_num: int
    goal: str
    tool_used: str
    args: str
    raw_output: Optional[str] = None
    parsed_output: Optional[str] = None
    outcome: str  # success, fail, stuck
    attempt_count: int = 1


class Session:
    """Manages session state and token tracking."""

    def __init__(
        self,
        project_id: str,
        playbook: str,
        target: str,
        tier: int = 1,
        token_budget: int = 4000,
        db_path: str = "kali_tools.db",
    ):
        self.project_id = project_id
        self.playbook = playbook
        self.target = target
        self.tier = tier
        self.token_budget = token_budget
        self.db_path = db_path
        self.token_used = 0
        self.session_id: Optional[int] = None
        self.started_at = datetime.now()

        # Create session in database
        self._create_session()

    def _create_session(self) -> None:
        """Create a new session record in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO sessions (project_id, playbook, target, tier, started_at, outcome)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                self.project_id,
                self.playbook,
                self.target,
                self.tier,
                self.started_at.isoformat(),
                None,
            ),
        )

        conn.commit()
        self.session_id = cursor.lastrowid
        conn.close()

    def add_step(
        self,
        step_num: int,
        goal: str,
        tool_used: str,
        args: str,
        outcome: str,
        raw_output: Optional[str] = None,
        parsed_output: Optional[str] = None,
        attempt_count: int = 1,
    ) -> None:
        """Record an execution step."""
        if not self.session_id:
            raise RuntimeError("Session not initialized")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO steps
            (session_id, step_num, goal, tool_used, args, raw_output,
             parsed_output, outcome, attempt_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.session_id,
                step_num,
                goal,
                tool_used,
                args,
                raw_output,
                parsed_output,
                outcome,
                attempt_count,
            ),
        )

        conn.commit()
        conn.close()

    def add_vulnerability(
        self,
        cve_id: str,
        tool_used: str,
        severity: str,
        attack_technique: Optional[str] = None,
        loot: Optional[str] = None,
    ) -> None:
        """Record a discovered vulnerability."""
        if not self.session_id:
            raise RuntimeError("Session not initialized")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO vulnerabilities
            (session_id, cve_id, tool_used, severity, attack_technique, loot)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (self.session_id, cve_id, tool_used, severity, attack_technique, loot),
        )

        conn.commit()
        conn.close()

    def increment_tokens(self, amount: int) -> None:
        """Add to token usage counter."""
        self.token_used += amount

    def remaining_budget(self) -> int:
        """Get remaining token budget."""
        return max(0, self.token_budget - self.token_used)

    def is_over_budget(self) -> bool:
        """Check if token budget exceeded."""
        return self.token_used >= self.token_budget

    def finish(self, outcome: str) -> None:
        """Mark session as finished."""
        if not self.session_id:
            raise RuntimeError("Session not initialized")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        now = datetime.now()
        cursor.execute(
            """
            UPDATE sessions
            SET finished_at = ?, outcome = ?
            WHERE id = ?
            """,
            (now.isoformat(), outcome, self.session_id),
        )

        conn.commit()
        conn.close()

    def get_state(self) -> SessionState:
        """Get current session state."""
        return SessionState(
            session_id=self.session_id or 0,
            project_id=self.project_id,
            playbook=self.playbook,
            target=self.target,
            tier=self.tier,
            started_at=self.started_at,
            token_budget=self.token_budget,
            token_used=self.token_used,
        )

    def summary(self) -> str:
        """Get session summary."""
        return f"""Session {self.session_id}:
  Target: {self.target}
  Playbook: {self.playbook}
  Tier: {self.tier}
  Token Budget: {self.token_budget}
  Token Used: {self.token_used}
  Remaining: {self.remaining_budget()}
  Over Budget: {self.is_over_budget()}"""
