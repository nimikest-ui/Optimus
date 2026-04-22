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
        """Chat/conversation mode (placeholder)."""
        print("\n💬 Chat Mode")
        print("Not yet implemented")
        questionary.confirm("Press Enter to continue...").ask()

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
                    print(
                        f"  {tool:20} | {phase:20} | {rate_bar} {success_rate:.2f}",
                        style=SPECTRAL_STYLE,
                    )
            else:
                print("No tools found")

        questionary.confirm("Press Enter to continue...").ask()

    def db_editor_mode(self) -> None:
        """Database editor: view/edit tool table."""
        print("\n📊 Database Editor")
        print("Not yet implemented (would show interactive table)")
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
        print("\n📈 Reports")
        print("Not yet implemented (would show reports)")
        questionary.confirm("Press Enter to continue...").ask()

    def settings_mode(self) -> None:
        """Settings: LLM provider, token budget, tier, ingesters."""
        print("\n⚙️  Settings")

        import yaml

        try:
            with open("config/config.yaml") as f:
                config = yaml.safe_load(f)

            current_provider = config.get("llm_provider", "claude")
            current_model = config.get("llm_model", "claude-opus-4-6")
            current_budget = config.get("token_budget", 4000)

            print(f"\nCurrent settings:")
            print(f"  Provider: {current_provider}")
            print(f"  Model: {current_model}")
            print(f"  Token budget: {current_budget}")

        except Exception as e:
            print(f"Error reading config: {e}")

        print("\nSettings editing not yet fully implemented")
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
