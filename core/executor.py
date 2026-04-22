"""Safe tool execution with timeout + output collection."""

import subprocess
import sqlite3
import json
import re
import time
from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel


class ExecutorResult(BaseModel):
    """Result of tool execution."""

    tool_name: str
    exit_code: int
    stdout: str
    stderr: str
    output_files: List[str]  # Paths to files created by tool
    elapsed_time: float  # Seconds
    success_pattern_matched: Optional[str] = None  # Which pattern matched (if any)


class Executor:
    """Safely executes tools with timeout + output collection."""

    def __init__(self, db_path: str = "kali_tools.db"):
        self.db_path = db_path

    def execute(
        self,
        tool_name: str,
        args: List[str],
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
    ) -> ExecutorResult:
        """
        Execute a tool safely.

        Args:
            tool_name: Name of tool to execute
            args: Arguments (list, no shell)
            timeout: Override timeout (seconds)
            working_dir: Working directory for tool execution

        Returns:
            ExecutorResult with stdout, stderr, exit_code, files created
        """
        # Get metadata for tool
        metadata = self._get_metadata(tool_name)

        # Determine timeout
        if timeout is None:
            timeout = metadata.get("timeout_seconds", 60)

        # Build command (argv-only, NO shell=True)
        command = [tool_name] + args

        start_time = time.time()
        stdout = ""
        stderr = ""
        exit_code = -1
        pattern_matched = None
        output_files = []

        try:
            if metadata.get("execution_type") == "long-running":
                # Long-running tool: watch for success patterns or timeout
                result = self._run_long_running(
                    command, timeout, metadata, working_dir
                )
                stdout = result["stdout"]
                stderr = result["stderr"]
                exit_code = result["exit_code"]
                pattern_matched = result.get("pattern_matched")
            else:
                # One-shot tool: simple run with timeout
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=working_dir,
                    shell=False,
                )
                stdout = result.stdout
                stderr = result.stderr
                exit_code = result.returncode

        except subprocess.TimeoutExpired as e:
            # Tool timed out
            stderr = f"Tool timeout after {timeout} seconds"
            exit_code = 124  # Standard timeout exit code

        except FileNotFoundError:
            stderr = f"Tool '{tool_name}' not found"
            exit_code = 127

        except Exception as e:
            stderr = f"Execution error: {str(e)}"
            exit_code = 1

        # Collect output files if applicable
        output_method = metadata.get("output_method", "stdout")
        if output_method in ["file", "files"]:
            output_files = self._collect_output_files(
                metadata, working_dir or "."
            )

        elapsed_time = time.time() - start_time

        return ExecutorResult(
            tool_name=tool_name,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            output_files=output_files,
            elapsed_time=elapsed_time,
            success_pattern_matched=pattern_matched,
        )

    def _get_metadata(self, tool_name: str) -> dict:
        """Get tool metadata from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT execution_type, timeout_seconds, output_method,
                       output_files_pattern, success_patterns, parser_type
                FROM tool_metadata
                WHERE tool_name = ?
                """,
                (tool_name,),
            )

            row = cursor.fetchone()
            conn.close()

            if row:
                return {
                    "execution_type": row[0] or "one-shot",
                    "timeout_seconds": row[1] or 60,
                    "output_method": row[2] or "stdout",
                    "output_files_pattern": row[3],
                    "success_patterns": json.loads(row[4]) if row[4] else [],
                    "parser_type": row[5] or "regex",
                }

        except Exception as e:
            print(f"Error getting metadata for {tool_name}: {e}")

        # Return smart defaults
        return {
            "execution_type": "one-shot",
            "timeout_seconds": 60,
            "output_method": "stdout",
            "output_files_pattern": None,
            "success_patterns": [],
            "parser_type": "regex",
        }

    def _run_long_running(
        self, command: List[str], timeout: int, metadata: dict, working_dir: Optional[str]
    ) -> dict:
        """Run long-running tool, watch for success patterns, kill on timeout."""
        import signal

        success_patterns = metadata.get("success_patterns", [])
        pattern_matched = None

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=working_dir,
                shell=False,
            )

            start_time = time.time()
            stdout_data = ""
            stderr_data = ""

            # Monitor process output
            while time.time() - start_time < timeout:
                try:
                    # Read available output (non-blocking)
                    stdout, stderr = process.communicate(timeout=0.1)
                    stdout_data += stdout
                    stderr_data += stderr

                    # Check for success patterns
                    for pattern in success_patterns:
                        if re.search(pattern, stdout_data, re.IGNORECASE):
                            pattern_matched = pattern
                            process.terminate()
                            break

                    # Check if process finished
                    if process.poll() is not None:
                        break

                except subprocess.TimeoutExpired:
                    # Process still running, continue
                    pass

            # Force kill if still running
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()

            return {
                "exit_code": process.returncode or 0,
                "stdout": stdout_data,
                "stderr": stderr_data,
                "pattern_matched": pattern_matched,
            }

        except Exception as e:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": str(e),
                "pattern_matched": None,
            }

    def _collect_output_files(self, metadata: dict, working_dir: str) -> List[str]:
        """Collect output files created by tool."""
        pattern = metadata.get("output_files_pattern")
        if not pattern:
            return []

        # Convert glob-like pattern to regex
        if pattern.startswith("-"):
            # Pattern like "-01.csv" - match files ending with this
            regex_pattern = f".*{re.escape(pattern)}$"
        elif pattern.startswith("*"):
            # Pattern like "*.csv" - match extension
            regex_pattern = f".*{re.escape(pattern[1:])}$"
        else:
            regex_pattern = pattern

        # Find matching files in working directory
        matched_files = []
        try:
            for file_path in Path(working_dir).iterdir():
                if re.match(regex_pattern, file_path.name):
                    matched_files.append(str(file_path))
        except Exception as e:
            print(f"Error collecting output files: {e}")

        return matched_files
