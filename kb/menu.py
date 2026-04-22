"""Interactive CLI menu with arrow key navigation (questionary-based)."""

import sys
from typing import Optional
import questionary
from questionary import Style

# Custom style for Spectral Analyst aesthetic
SPECTRAL_STYLE = Style([
    ('qmark', 'fg:#D4A843 bold'),      # Gold highlights
    ('question', 'fg:#D4A843 bold'),   # Gold for questions
    ('answer', 'fg:#C44B22 bold'),     # Terracotta for answers
    ('pointer', 'fg:#C44B22 bold'),    # Terracotta for pointer
    ('highlighted', 'fg:#C44B22 bold'), # Terracotta highlight
    ('selected', 'fg:#D4A843'),        # Gold for selected
    ('separator', 'fg:#666666'),
    ('instruction', 'fg:#888888'),
    ('text', 'fg:#D4D4D4'),           # Light text
])


class InteractiveMenu:
    """Main interactive CLI menu system."""

    def __init__(self):
        self.running = True

    def main_menu(self) -> None:
        """Display main menu and route to selected mode."""
        while self.running:
            choice = questionary.select(
                "OPTIMUS — Pentesting Automation Platform",
                choices=[
                    questionary.Choice("💬 Chat", "chat"),
                    questionary.Choice("📚 KB Research (Deep Dive)", "kb_research"),
                    questionary.Choice("🎯 Run Playbook", "run_playbook"),
                    questionary.Choice("🔧 Tools Browser", "tools"),
                    questionary.Choice("📊 Database Editor", "db"),
                    questionary.Choice("📋 Session History", "sessions"),
                    questionary.Choice("📈 Reports", "reports"),
                    questionary.Choice("⚙️  Settings", "settings"),
                    questionary.Choice("🔄 Sync Ingesters", "sync"),
                    questionary.Choice("🏥 Doctor (Diagnostics)", "doctor"),
                    questionary.Choice("❌ Exit", "exit"),
                ],
                style=SPECTRAL_STYLE,
                use_shortcuts=True,
            ).ask()

            if choice is None:  # User pressed Ctrl+C
                self.running = False
                break

            self.route_to_mode(choice)

    def route_to_mode(self, choice: str) -> None:
        """Route to the selected mode."""
        if choice == "chat":
            self.chat_mode()
        elif choice == "kb_research":
            self.kb_research_mode()
        elif choice == "run_playbook":
            self.run_playbook_mode()
        elif choice == "tools":
            self.tools_browser_mode()
        elif choice == "db":
            self.db_editor_mode()
        elif choice == "sessions":
            self.sessions_mode()
        elif choice == "reports":
            self.reports_mode()
        elif choice == "settings":
            self.settings_mode()
        elif choice == "sync":
            self.sync_mode()
        elif choice == "doctor":
            self.doctor_mode()
        elif choice == "exit":
            self.running = False

    def chat_mode(self) -> None:
        """Chat mode: intelligent agent execution."""
        print("\n💬 Chat with Intelligent Agent")
        print("─" * 60)

        mission = questionary.text(
            "What's your mission? (e.g., 'find web vulnerabilities', 'list bluetooth devices', 'scan for open ports'):",
            style=SPECTRAL_STYLE,
        ).ask()

        if not mission:
            return

        target = questionary.text(
            "Target or context (IP, domain, network, or description - e.g., '192.168.1.0/24', 'nearby devices', 'local network'):",
            style=SPECTRAL_STYLE,
        ).ask()

        if not target:
            # Allow mission-only execution (target can be inferred from mission)
            target = "local"

        tier = questionary.select(
            "Execution tier:",
            choices=[
                questionary.Choice("1 - Passive/Reconnaissance (safe)", 1),
                questionary.Choice("2 - Active Scanning (may alert)", 2),
                questionary.Choice("3 - Destructive/Exploit (high risk)", 3),
            ],
            style=SPECTRAL_STYLE,
        ).ask()

        if tier is None:
            return

        print(f"\n[AGENT] Starting mission: {mission}")
        print(f"[AGENT] Target: {target}")
        print(f"[AGENT] Tier: {tier}")
        print("─" * 60)

        try:
            from core.agent import IntelligentAgent

            agent = IntelligentAgent()
            result = agent.execute_mission(
                mission=mission,
                target=target,
                tier=tier,
            )

            print("\n" + "─" * 60)
            print("[AGENT] ✅ Mission Complete!")
            print(f"  Session: {result['session_id']}")
            print(f"  Outcome: {result['outcome']}")
            print(f"  Tools used: {len(result['tools_used'])}")
            print(f"  CVEs found: {len(result['cves_found'])}")

        except Exception as e:
            print(f"\n[AGENT] ✗ Error: {str(e)}")

        questionary.confirm("\nPress Enter to return to menu...").ask()

    def kb_research_mode(self) -> None:
        """KB research mode: run ingesters, view results."""
        print("\n📚 KB Research Mode")

        subject = questionary.text(
            "Research subject (e.g., 'web vulnerabilities'):",
            style=SPECTRAL_STYLE,
        ).ask()

        if subject:
            from kb.cli import agent_init

            # Run agent_init with the subject
            import subprocess
            result = subprocess.run(
                ["python", "-m", "kb.cli", "agent-init", subject],
                capture_output=False,
            )

            if result.returncode == 0:
                print("\n✓ Playbook generated successfully")
            else:
                print("\n✗ Failed to generate playbook")

        questionary.confirm("Press Enter to continue...").ask()

    def run_playbook_mode(self) -> None:
        """Run playbook mode: select and execute."""
        print("\n🎯 Run Playbook Mode")

        from pathlib import Path

        playbooks_dir = Path("artifacts/playbooks")
        playbooks = sorted(playbooks_dir.glob("*.yaml"))

        if not playbooks:
            print("No playbooks found")
            questionary.confirm("Press Enter to continue...").ask()
            return

        playbook_choices = [
            questionary.Choice(p.stem, str(p)) for p in playbooks
        ]

        playbook = questionary.select(
            "Select playbook:",
            choices=playbook_choices,
            style=SPECTRAL_STYLE,
        ).ask()

        if playbook:
            target = questionary.text(
                "Target (IP or domain):",
                style=SPECTRAL_STYLE,
            ).ask()

            if target:
                tier = questionary.select(
                    "Execution tier:",
                    choices=[
                        questionary.Choice("1 (Passive/Reconnaissance)", 1),
                        questionary.Choice("2 (Active)", 2),
                        questionary.Choice("3 (Destructive)", 3),
                    ],
                    style=SPECTRAL_STYLE,
                ).ask()

                if tier:
                    import subprocess

                    result = subprocess.run(
                        [
                            "python",
                            "-m",
                            "kb.cli",
                            "run",
                            playbook,
                            "--target",
                            target,
                            "--tier",
                            str(tier),
                        ],
                        capture_output=False,
                    )

                    questionary.confirm("Press Enter to continue...").ask()

    def tools_browser_mode(self) -> None:
        """Tools browser: search and filter tools."""
        print("\n🔧 Tools Browser")

        search_query = questionary.text(
            "Search tools (keyword):",
            style=SPECTRAL_STYLE,
        ).ask()

        if search_query:
            import sqlite3

            conn = sqlite3.connect("kali_tools.db")
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT tool_name, one_line_desc, attack_phase, success_rate
                FROM kali_tools
                WHERE tool_name LIKE ? OR one_line_desc LIKE ?
                ORDER BY success_rate DESC
                LIMIT 20
                """,
                (f"%{search_query}%", f"%{search_query}%"),
            )

            results = cursor.fetchall()
            conn.close()

            if results:
                print(f"\nFound {len(results)} tools:")
                for tool, desc, phase, success_rate in results:
                    rate_bar = "█" * int(success_rate * 10) + "░" * (10 - int(success_rate * 10))
                    print(f"  {tool:20} | {phase:20} | {rate_bar} {success_rate:.2f}")
            else:
                print("No tools found")

        questionary.confirm("Press Enter to continue...").ask()

    def db_editor_mode(self) -> None:
        """Database editor: view/edit tool table."""
        print("\n📊 Database Editor")

        import sqlite3

        action = questionary.select(
            "What would you like to do?",
            choices=[
                questionary.Choice("View tools by search", "search"),
                questionary.Choice("View tools by attack phase", "phase"),
                questionary.Choice("Update tool success rate", "update"),
                questionary.Choice("Back to menu", "back"),
            ],
            style=SPECTRAL_STYLE,
        ).ask()

        if action == "search":
            search = questionary.text(
                "Search for tool (name or keyword):",
                style=SPECTRAL_STYLE,
            ).ask()

            if search:
                conn = sqlite3.connect("kali_tools.db")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT tool_name, attack_phase, success_rate, use_count
                    FROM kali_tools
                    WHERE tool_name LIKE ? OR one_line_desc LIKE ?
                    LIMIT 10
                    """,
                    (f"%{search}%", f"%{search}%"),
                )
                results = cursor.fetchall()
                conn.close()

                if results:
                    print(f"\nFound {len(results)} tools:")
                    print(f"{'Tool':<25} {'Phase':<20} {'Score':<8} {'Uses':<6}")
                    print("─" * 60)
                    for tool, phase, score, uses in results:
                        print(f"{tool:<25} {phase:<20} {score:<8.2f} {uses:<6}")
                else:
                    print("No tools found")

        elif action == "phase":
            conn = sqlite3.connect("kali_tools.db")
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT attack_phase FROM kali_tools ORDER BY attack_phase")
            phases = [row[0] for row in cursor.fetchall()]
            conn.close()

            phase = questionary.select(
                "Select attack phase:",
                choices=phases,
                style=SPECTRAL_STYLE,
            ).ask()

            if phase:
                conn = sqlite3.connect("kali_tools.db")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT tool_name, success_rate, use_count
                    FROM kali_tools
                    WHERE attack_phase = ?
                    ORDER BY success_rate DESC
                    LIMIT 20
                    """,
                    (phase,),
                )
                results = cursor.fetchall()
                conn.close()

                print(f"\nTools in '{phase}' phase ({len(results)} total):")
                print(f"{'Tool':<25} {'Score':<8} {'Uses':<6}")
                print("─" * 40)
                for tool, score, uses in results:
                    print(f"{tool:<25} {score:<8.2f} {uses:<6}")

        elif action == "update":
            tool_name = questionary.text(
                "Tool name to update:",
                style=SPECTRAL_STYLE,
            ).ask()

            if tool_name:
                new_score = questionary.text(
                    "New success rate (0.0-1.0):",
                    style=SPECTRAL_STYLE,
                ).ask()

                try:
                    score = float(new_score)
                    if 0.0 <= score <= 1.0:
                        conn = sqlite3.connect("kali_tools.db")
                        cursor = conn.cursor()
                        cursor.execute(
                            "UPDATE kali_tools SET success_rate = ? WHERE tool_name = ?",
                            (score, tool_name),
                        )
                        conn.commit()
                        conn.close()
                        print(f"✓ Updated {tool_name} score to {score}")
                    else:
                        print("✗ Score must be between 0.0 and 1.0")
                except ValueError:
                    print("✗ Invalid score format")

        questionary.confirm("Press Enter to continue...").ask()

    def sessions_mode(self) -> None:
        """Session history: view past executions."""
        print("\n📋 Session History")

        import sqlite3

        conn = sqlite3.connect("kali_tools.db")
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, project_id, playbook, target, outcome, started_at
            FROM sessions
            ORDER BY started_at DESC
            LIMIT 20
            """
        )

        sessions = cursor.fetchall()
        conn.close()

        if sessions:
            print(f"\nRecent sessions:")
            for session_id, project, playbook, target, outcome, started in sessions:
                outcome_emoji = "✓" if outcome == "success" else "⚠" if outcome == "partial" else "✗"
                print(
                    f"  [{session_id:3}] {outcome_emoji} {project:20} → {target:15} ({playbook})",
                    style=SPECTRAL_STYLE,
                )
        else:
            print("No sessions found")

        questionary.confirm("Press Enter to continue...").ask()

    def reports_mode(self) -> None:
        """Reports: view execution reports."""
        print("\n📈 Reports & Analysis")

        import sqlite3
        from pathlib import Path

        action = questionary.select(
            "What would you like to view?",
            choices=[
                questionary.Choice("Session summary", "summary"),
                questionary.Choice("Recent successful runs", "success"),
                questionary.Choice("Tool statistics", "stats"),
                questionary.Choice("Saved playbooks", "playbooks"),
                questionary.Choice("Back to menu", "back"),
            ],
            style=SPECTRAL_STYLE,
        ).ask()

        if action == "summary":
            conn = sqlite3.connect("kali_tools.db")
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM sessions")
            total_sessions = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE outcome = 'success'")
            successful = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE outcome = 'partial'")
            partial = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM steps")
            total_steps = cursor.fetchone()[0]

            conn.close()

            success_rate = (successful / total_sessions * 100) if total_sessions > 0 else 0

            print("\n📊 Overall Statistics:")
            print(f"  Total sessions: {total_sessions}")
            print(f"  Successful: {successful} ({success_rate:.1f}%)")
            print(f"  Partial success: {partial}")
            print(f"  Total steps executed: {total_steps}")

        elif action == "success":
            conn = sqlite3.connect("kali_tools.db")
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT id, project_id, target, started_at
                FROM sessions
                WHERE outcome = 'success'
                ORDER BY started_at DESC
                LIMIT 10
                """,
            )

            sessions = cursor.fetchall()
            conn.close()

            if sessions:
                print("\n✓ Recent Successful Runs:")
                for sid, project, target, started in sessions:
                    print(f"  [{sid}] {project:<20} → {target:<15} ({started})")
            else:
                print("No successful sessions found")

        elif action == "stats":
            conn = sqlite3.connect("kali_tools.db")
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT tool_name, COUNT(*) as uses, AVG(success_rate) as avg_score
                FROM kali_tools
                WHERE use_count > 0
                ORDER BY use_count DESC
                LIMIT 15
                """,
            )

            results = cursor.fetchall()
            conn.close()

            if results:
                print("\n🔧 Most Used Tools:")
                print(f"{'Tool':<25} {'Uses':<6} {'Avg Score':<10}")
                print("─" * 42)
                for tool, uses, score in results:
                    print(f"{tool:<25} {uses:<6} {score:<10.2f}")
            else:
                print("No tool usage data yet")

        elif action == "playbooks":
            playbooks_dir = Path("artifacts/playbooks")
            playbooks = sorted(playbooks_dir.glob("*.yaml"))

            if playbooks:
                print(f"\n📋 Saved Playbooks ({len(playbooks)} total):")
                for pb in playbooks:
                    size = pb.stat().st_size
                    print(f"  • {pb.name:<50} ({size} bytes)")
            else:
                print("No playbooks saved yet")

        questionary.confirm("Press Enter to continue...").ask()

    def settings_mode(self) -> None:
        """Settings: LLM provider, token budget, tier, ingesters."""
        print("\n⚙️  Settings")

        import yaml
        import os

        try:
            with open("config/config.yaml") as f:
                config = yaml.safe_load(f) or {}

            current_provider = config.get("llm_provider", "claude")
            current_model = config.get("llm_model", "claude-opus-4-6")
            current_budget = config.get("token_budget", 4000)
            current_tier = config.get("tier_default", 1)

            print(f"\nCurrent settings:")
            print(f"  Provider: {current_provider}")
            print(f"  Model: {current_model}")
            print(f"  Token budget: {current_budget}")
            print(f"  Default tier: {current_tier}")

            action = questionary.select(
                "What would you like to change?",
                choices=[
                    questionary.Choice("LLM Provider", "provider"),
                    questionary.Choice("LLM Model", "model"),
                    questionary.Choice("Token Budget", "budget"),
                    questionary.Choice("Default Tier", "tier"),
                    questionary.Choice("Back to menu", "back"),
                ],
                style=SPECTRAL_STYLE,
            ).ask()

            if action == "provider":
                provider = questionary.select(
                    "Select LLM provider:",
                    choices=["claude", "grok", "groq", "openai"],
                    style=SPECTRAL_STYLE,
                ).ask()

                if provider:
                    config["llm_provider"] = provider
                    print(f"✓ Provider set to {provider}")

            elif action == "model":
                model = questionary.text(
                    "Enter model name (e.g., claude-opus-4-6):",
                    style=SPECTRAL_STYLE,
                ).ask()

                if model:
                    config["llm_model"] = model
                    print(f"✓ Model set to {model}")

            elif action == "budget":
                budget = questionary.text(
                    "Enter token budget (default 4000):",
                    style=SPECTRAL_STYLE,
                ).ask()

                try:
                    budget_int = int(budget)
                    config["token_budget"] = budget_int
                    print(f"✓ Token budget set to {budget_int}")
                except ValueError:
                    print("✗ Invalid number")
                    questionary.confirm("Press Enter to continue...").ask()
                    return

            elif action == "tier":
                tier = questionary.select(
                    "Select default tier:",
                    choices=[
                        questionary.Choice("1 - Passive", 1),
                        questionary.Choice("2 - Active", 2),
                        questionary.Choice("3 - Destructive", 3),
                    ],
                    style=SPECTRAL_STYLE,
                ).ask()

                if tier:
                    config["tier_default"] = tier
                    print(f"✓ Default tier set to {tier}")

            # Save config if changes were made
            if action != "back":
                with open("config/config.yaml", "w") as f:
                    yaml.dump(config, f, default_flow_style=False)
                print("✓ Configuration saved")

        except Exception as e:
            print(f"Error: {e}")

        questionary.confirm("Press Enter to continue...").ask()

    def sync_mode(self) -> None:
        """Sync all ingesters."""
        print("\n🔄 Syncing Ingesters")

        import subprocess

        result = subprocess.run(
            ["python", "-m", "kb.cli", "sync", "--verbose"],
            capture_output=False,
        )

        questionary.confirm("Press Enter to continue...").ask()

    def doctor_mode(self) -> None:
        """Run diagnostics."""
        print("\n🏥 System Diagnostics")

        import subprocess

        result = subprocess.run(
            ["python", "-m", "kb.cli", "doctor"],
            capture_output=False,
        )

        questionary.confirm("Press Enter to continue...").ask()


def main() -> None:
    """Entry point for interactive menu."""
    try:
        menu = InteractiveMenu()
        menu.main_menu()
        print("\nGoodbye!")
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
