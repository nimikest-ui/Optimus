"""CLI entrypoint for Optimus."""

import os
import sys
import sqlite3
import yaml
import subprocess
from pathlib import Path
from typing import Optional
import typer

from kb.ingesters.mitre_attck import MitreIngestor
from kb.ingesters.nvd_ingester import NVDIngester
from kb.ingesters.cisa_ingester import CISAIngester
from kb.ingesters.api_ingesters import (
    OTXIngester,
    VTIngester,
    ShodanIngester,
    ZoomEyeIngester,
    CensysIngester,
    MetasploitIngester,
    CVEAggregatorIngester,
)
from kb.compiler import Compiler, PlaybookPlan
from core.session import Session
from core.executor import Executor
from core.output_parser import OutputParser
from core.reflect import Reflector
from core.planner import ExecutionStep
from db.scanner import ToolScanner

app = typer.Typer(
    help="Optimus — Unified Pentesting Automation Platform",
    invoke_without_command=False,
)


def ensure_db_initialized() -> None:
    """Auto-initialize DB if missing (called on CLI startup)."""
    db_path = "kali_tools.db"

    # If DB doesn't exist, run init automatically
    if not Path(db_path).exists():
        typer.echo("[STARTUP] Database not found. Running initialization...")
        try:
            # Run migrations
            result = subprocess.run(
                ["alembic", "upgrade", "head"],
                cwd=".",
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                typer.echo(f"[STARTUP] ✗ Migration failed: {result.stderr}")
                return

            # Scan tools
            scanner = ToolScanner(db_path)
            count = scanner.scan_and_populate()
            typer.echo(f"[STARTUP]   ✓ Scanned {count} tools")

        except Exception as e:
            typer.echo(f"[STARTUP] Warning: Auto-init failed: {e}")
            typer.echo(f"[STARTUP] Run 'kb init' manually to initialize")


@app.command()
def init(scan_limit: int = typer.Option(None, "--limit", help="Limit number of tools to scan (None = all)")) -> None:
    """Initialize Optimus: run migrations, scan installed tools, sync ingesters."""
    db_path = "kali_tools.db"

    # Step 1: Run alembic migrations
    typer.echo("[INIT] Step 1: Running database migrations...")
    try:
        result = subprocess.run(
            ["alembic", "upgrade", "head"],
            cwd=".",
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            typer.echo(f"[INIT] ✗ Alembic failed: {result.stderr}")
            raise typer.Exit(code=1)
        typer.echo("[INIT]   ✓ Database schema initialized")
    except Exception as e:
        typer.echo(f"[INIT] ✗ Migration error: {e}")
        raise typer.Exit(code=1)

    # Step 2: Scan installed tools
    typer.echo("[INIT] Step 2: Scanning installed tools...")
    try:
        scanner = ToolScanner(db_path)
        count = scanner.scan_and_populate(limit=scan_limit)
        typer.echo(f"[INIT]   ✓ Scanned {count} tools from system")
    except Exception as e:
        typer.echo(f"[INIT] ✗ Scanner error: {e}")
        raise typer.Exit(code=1)

    # Step 3: Run ingester sync
    typer.echo("[INIT] Step 3: Syncing ingesters (MITRE, NVD, CISA, etc.)...")
    try:
        sync(verbose=False)
    except Exception as e:
        typer.echo(f"[INIT] ✗ Sync error: {e}")
        raise typer.Exit(code=1)

    typer.echo("\n[INIT] ✓ Optimus initialized! Ready to use:")
    typer.echo("  kb agent 'find vulnerabilities' --target 10.0.0.1")
    typer.echo("  kb research 'Apache CVE'")
    typer.echo("  kb interactive")


@app.command()
def agent(
    mission: str = typer.Argument(..., help="Mission (e.g., 'find Apache vulnerabilities')"),
    target: str = typer.Option(..., "--target", "-t", help="Target IP or domain"),
    tier: int = typer.Option(1, "--tier", min=1, max=3, help="Execution tier (1=passive, 2=active, 3=destructive)"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Project ID"),
) -> None:
    """Intelligent agent: uses research + reflector to auto-select and execute tools."""
    db_path = "kali_tools.db"

    # Check if DB exists
    if not Path(db_path).exists():
        typer.echo("[AGENT] ERROR: kali_tools.db not found. Run 'alembic upgrade head' first.")
        raise typer.Exit(code=1)

    from core.agent import IntelligentAgent

    agent_instance = IntelligentAgent(db_path, project or "auto")

    try:
        result = agent_instance.execute_mission(
            mission=mission,
            target=target,
            tier=tier,
        )

        typer.echo(f"\n[AGENT] Mission complete!")
        typer.echo(f"  Session: {result['session_id']}")
        typer.echo(f"  Outcome: {result['outcome']}")
        typer.echo(f"  Tools used: {len(result['tools_used'])}")
        typer.echo(f"  CVEs found: {len(result['cves_found'])}")

    except Exception as e:
        typer.echo(f"[AGENT] Error: {e}")
        raise typer.Exit(code=1)


@app.command()
def research(
    query: str = typer.Argument(..., help="Research topic (e.g., 'airmon-ng', 'Apache CVE')"),
    sources: Optional[str] = typer.Option(None, "--sources", "-s", help="Comma-separated sources (google,github,exploit-db,threat-feeds)"),
) -> None:
    """Deep research: search online sources for vulnerabilities, exploits, tools."""
    db_path = "kali_tools.db"

    # Check if DB exists
    if not Path(db_path).exists():
        typer.echo("[RESEARCH] ERROR: kali_tools.db not found. Run 'alembic upgrade head' first.")
        raise typer.Exit(code=1)

    typer.echo(f"[RESEARCH] Researching: {query}")

    from kb.researcher import Researcher

    researcher = Researcher(db_path)

    # Parse sources
    source_list = None
    if sources:
        source_list = [s.strip() for s in sources.split(",")]

    # Run research
    findings = researcher.research(query, source_list)

    typer.echo(f"\n[RESEARCH] Found {len(findings)} results:")

    # Display findings
    for i, finding in enumerate(findings, 1):
        typer.echo(f"\n  [{i}] {finding.title}")
        typer.echo(f"      Source: {finding.source}")
        if finding.cves:
            typer.echo(f"      CVEs: {', '.join(finding.cves)}")
        if finding.tools:
            typer.echo(f"      Tools: {', '.join(finding.tools)}")
        if finding.severity:
            typer.echo(f"      Severity: {finding.severity}")
        typer.echo(f"      URL: {finding.url}")

    typer.echo(f"\n[RESEARCH] Results stored in database for agent use")


@app.command()
def interactive() -> None:
    """Start interactive menu with arrow key navigation."""
    from kb.menu import main
    main()


@app.command()
def sync(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    """Sync all ingesters → update kali_tools.db with latest tools, CVEs, techniques."""
    db_path = "kali_tools.db"

    typer.echo("[SYNC] Starting ingester synchronization...")
    typer.echo(f"[SYNC] Database: {db_path}")

    # Check if DB exists
    if not Path(db_path).exists():
        typer.echo("[SYNC] ERROR: kali_tools.db not found. Run 'alembic upgrade head' first.")
        raise typer.Exit(code=1)

    # Update MITRE phases first
    try:
        mitre = MitreIngestor(db_path)
        mitre.update_tool_phases()
        typer.echo("  ✓ MITRE ATT&CK: success")
        results = [{"status": "success"}]
    except Exception as e:
        typer.echo(f"  ✗ MITRE ATT&CK: failed")
        if verbose:
            typer.echo(f"     {str(e)}")
        results = [{"status": "failed"}]

    # Initialize other ingesters
    ingesters = [
        ("NVD", NVDIngester(db_path)),
        ("CISA KEV", CISAIngester(db_path)),
        ("OTX", OTXIngester(db_path)),
        ("VirusTotal", VTIngester(db_path)),
        ("Shodan", ShodanIngester(db_path)),
        ("ZoomEye", ZoomEyeIngester(db_path)),
        ("Censys", CensysIngester(db_path)),
        ("Metasploit", MetasploitIngester(db_path)),
        ("CVE Aggregator", CVEAggregatorIngester(db_path)),
    ]

    for name, ingester in ingesters:
        try:
            result = ingester.run()
            results.append(result)
            status_emoji = "✓" if result["status"] == "success" else "✗"
            typer.echo(f"  {status_emoji} {name}: {result['status']}")
            if verbose and result.get("error"):
                typer.echo(f"     Error: {result['error']}")
        except Exception as e:
            typer.echo(f"  ✗ {name}: exception during ingestion")
            if verbose:
                typer.echo(f"     {str(e)}")

    # Summary
    successful = sum(1 for r in results if r["status"] == "success")
    typer.echo(f"\n[SYNC] Complete: {successful}/{len(ingesters)} ingesters successful")


@app.command()
def agent_init(subject: str, max_steps: int = typer.Option(10), output: Optional[str] = typer.Option(None, "--output", "-o")) -> None:
    """Deep research: KB agent runs ingesters → synthesizes new playbook YAML."""
    db_path = "kali_tools.db"
    project_id = f"research-{subject.replace(' ', '-')}"

    typer.echo(f"[AGENT] Researching: {subject}")

    # Check if DB exists
    if not Path(db_path).exists():
        typer.echo("[AGENT] ERROR: kali_tools.db not found. Run 'alembic upgrade head' first.")
        raise typer.Exit(code=1)

    # Run ingesters to gather KB data
    typer.echo("\n[AGENT] Phase 1: Knowledge gathering (running ingesters)...")
    sync_cmd = sync.__wrapped__ if hasattr(sync, '__wrapped__') else sync
    # Just run the ingesters inline
    ingesters_to_run = [
        NVDIngester(db_path),
        CISAIngester(db_path),
    ]

    for ingester in ingesters_to_run:
        try:
            ingester.run()
        except Exception as e:
            typer.echo(f"  Warning: Ingester {ingester.source_name} failed: {e}")

    # Compile playbook from research
    typer.echo("\n[AGENT] Phase 2: Compiling playbook...")
    compiler = Compiler(db_path)

    # For now, compile by intent
    plan = compiler.compile_from_intent(project_id, subject, subject, max_steps=max_steps)

    # Save playbook
    playbook_path = compiler.save_playbook(plan)
    typer.echo(f"[AGENT] Playbook saved to: {playbook_path}")

    if output:
        # Copy to specified output path
        import shutil
        shutil.copy(playbook_path, output)
        typer.echo(f"[AGENT] Also copied to: {output}")


@app.command(name="run")
def run(
    playbook_file: str = typer.Argument(..., help="Path to playbook YAML file"),
    target: str = typer.Option(..., "--target", "-t", help="Target IP or domain"),
    tier: int = typer.Option(1, "--tier", min=1, max=3, help="Execution tier (1=passive, 2=active, 3=destructive)"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Project ID"),
) -> None:
    """Execute a playbook against a target."""
    db_path = "kali_tools.db"

    # Validate inputs
    playbook_path = Path(playbook_file)
    if not playbook_path.exists():
        typer.echo(f"ERROR: Playbook not found: {playbook_file}")
        raise typer.Exit(code=1)

    # Load playbook
    try:
        with open(playbook_path) as f:
            playbook_data = yaml.safe_load(f)
    except Exception as e:
        typer.echo(f"ERROR: Failed to load playbook: {e}")
        raise typer.Exit(code=1)

    project_id = project or playbook_data.get("name", "run")
    playbook_name = playbook_path.stem

    typer.echo(f"[RUN] Starting execution")
    typer.echo(f"  Playbook: {playbook_name}")
    typer.echo(f"  Target: {target}")
    typer.echo(f"  Tier: {tier}")
    typer.echo(f"  Project: {project_id}")

    # Create session
    session = Session(
        project_id=project_id,
        playbook=playbook_name,
        target=target,
        tier=tier,
        token_budget=4000,
        db_path=db_path,
    )

    if not session.session_id:
        typer.echo("ERROR: Failed to create session")
        raise typer.Exit(code=1)

    typer.echo(f"  Session ID: {session.session_id}")

    # Execute steps
    executor = Executor(db_path)
    parser = OutputParser()
    reflector = Reflector(db_path)

    executed_steps = []
    all_success = True

    for step_data in playbook_data.get("steps", []):
        step_num = step_data.get("step", 1)
        goal = step_data.get("goal", "")
        tool = step_data.get("tool", "")
        args = step_data.get("args", "")
        success_criteria = step_data.get("success_criteria", "")
        timeout = step_data.get("timeout", 30)

        # Replace {TARGET} placeholder
        args = args.replace("{TARGET}", target)

        typer.echo(f"\n[STEP {step_num}] {goal}")
        typer.echo(f"  Tool: {tool}")
        typer.echo(f"  Args: {args}")

        # Execute tool (parse args string into list)
        args_list = args.split() if args else []
        result = executor.execute(
            tool_name=tool,
            args=args_list,
            timeout=timeout,
        )

        if result.exit_code == 0:
            typer.echo(f"  ✓ Success")
            outcome = "success"

            # Parse output
            try:
                parsed = parser.parse(tool, result.stdout)
                parsed_str = str(parsed)
            except Exception as e:
                typer.echo(f"  Warning: Failed to parse output: {e}")
                parsed_str = result.stdout

            # Record step
            session.add_step(
                step_num=step_num,
                goal=goal,
                tool_used=tool,
                args=args,
                outcome=outcome,
                raw_output=result.stdout,
                parsed_output=parsed_str,
                attempt_count=1,
            )

            executed_steps.append({
                "step_num": step_num,
                "goal": goal,
                "tool": tool,
                "args": args,
                "success_criteria": success_criteria,
                "timeout": timeout,
            })
        else:
            error_msg = result.stderr if result.stderr else f"exit code {result.exit_code}"
            typer.echo(f"  ✗ Failed: {error_msg}")
            outcome = "fail"
            all_success = False

            # Record failure
            session.add_step(
                step_num=step_num,
                goal=goal,
                tool_used=tool,
                args=args,
                outcome=outcome,
                raw_output=result.stdout,
                attempt_count=1,
            )

    # Update session outcome
    session.finish(outcome="success" if all_success else "partial")

    # Reflect on results
    if all_success and executed_steps:
        typer.echo("\n[REFLECT] Learning from successful execution...")
        try:
            from core.planner import ExecutionStep
            steps = [ExecutionStep(**s) for s in executed_steps]
            reflector.reflect_on_success(
                session_id=session.session_id,
                project_id=project_id,
                target=target,
                steps=steps,
            )
        except Exception as e:
            typer.echo(f"  Warning: Reflection failed: {e}")

    typer.echo(f"\n[RUN] Execution complete: {session.session_id}")


@app.command()
def doctor() -> None:
    """Diagnostic: check DB health, LLM key, scope files, tool install status."""
    db_path = "kali_tools.db"

    typer.echo("[DOCTOR] Running diagnostics...\n")

    # Check database
    typer.echo("1. Database:")
    if Path(db_path).exists():
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Check tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            typer.echo(f"   ✓ Database exists ({len(tables)} tables)")

            # Check kali_tools row count
            cursor.execute("SELECT COUNT(*) FROM kali_tools")
            count = cursor.fetchone()[0]
            typer.echo(f"   ✓ kali_tools: {count} tools")

            # Check for attack_phase population
            cursor.execute("SELECT COUNT(*) FROM kali_tools WHERE attack_phase IS NOT NULL")
            phase_count = cursor.fetchone()[0]
            typer.echo(f"   ✓ attack_phase: {phase_count}/{count} populated")

            # Check FTS5 index
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kali_tools_fts'")
            fts_exists = cursor.fetchone()
            typer.echo(f"   {'✓' if fts_exists else '✗'} FTS5 index: {'exists' if fts_exists else 'missing'}")

            conn.close()
        except Exception as e:
            typer.echo(f"   ✗ Database error: {e}")
    else:
        typer.echo(f"   ✗ Database not found: {db_path}")

    # Check LLM configuration
    typer.echo("\n2. LLM Provider:")
    config_path = Path("config/config.yaml")
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
            provider = config.get("llm_provider", "unknown")
            model = config.get("llm_model", "unknown")
            typer.echo(f"   ✓ Config found: {provider} / {model}")

            # Check API key
            key_env = f"{provider.upper()}_API_KEY"
            if os.getenv(key_env):
                typer.echo(f"   ✓ API key set ({key_env})")
            else:
                typer.echo(f"   ✗ API key not set ({key_env})")
        except Exception as e:
            typer.echo(f"   ✗ Config error: {e}")
    else:
        typer.echo(f"   ✗ Config not found: {config_path}")

    # Check scope files
    typer.echo("\n3. Scope Files:")
    scope_dir = Path("config/scope")
    if scope_dir.exists():
        scope_files = list(scope_dir.glob("*/scope.yaml"))
        typer.echo(f"   ✓ Scope directory exists ({len(scope_files)} projects)")
        for scope_file in scope_files[:5]:
            typer.echo(f"     - {scope_file.parent.name}")
        if len(scope_files) > 5:
            typer.echo(f"     ... and {len(scope_files) - 5} more")
    else:
        typer.echo(f"   ✗ Scope directory not found: {scope_dir}")

    # Check ingesters
    typer.echo("\n4. Ingesters:")
    try:
        from kb.ingesters.nvd_ingester import NVDIngester
        typer.echo("   ✓ NVD ingester available")
    except ImportError:
        typer.echo("   ✗ NVD ingester not available")

    try:
        from kb.ingesters.cisa_ingester import CISAIngester
        typer.echo("   ✓ CISA ingester available")
    except ImportError:
        typer.echo("   ✗ CISA ingester not available")

    # Check artifacts directory
    typer.echo("\n5. Artifacts:")
    playbooks_dir = Path("artifacts/playbooks")
    if playbooks_dir.exists():
        playbooks = list(playbooks_dir.glob("*.yaml"))
        typer.echo(f"   ✓ Playbooks directory exists ({len(playbooks)} playbooks)")
    else:
        typer.echo(f"   ✗ Playbooks directory not found: {playbooks_dir}")

    typer.echo("\n[DOCTOR] Diagnostics complete")


def main() -> None:
    """Main entry point."""
    ensure_db_initialized()
    app()


if __name__ == "__main__":
    main()
