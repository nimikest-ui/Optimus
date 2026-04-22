"""Scanner to populate kali_tools.db from installed packages and man pages."""

import subprocess
import gzip
import os
import re
import sqlite3
import json
from pathlib import Path
from typing import Optional
from db.metadata_extractor import MetadataExtractor


class ToolScanner:
    """Scans installed Kali tools from dpkg and man pages."""

    def __init__(self, db_path: str = "kali_tools.db"):
        self.db_path = db_path
        self.man_paths = [
            "/usr/share/man/man1",
            "/usr/share/man/man8",
            "/usr/share/man/man5",
            "/usr/share/man/man3",
        ]

    def get_installed_packages(self) -> list[dict[str, str]]:
        """Get list of installed packages from dpkg."""
        try:
            result = subprocess.run(
                ["dpkg", "-l"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            packages = []
            for line in result.stdout.split("\n"):
                if line.startswith("ii"):
                    parts = line.split()
                    if len(parts) >= 3:
                        pkg_name = parts[1]
                        packages.append({"pkg_name": pkg_name})
            return packages
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"Error getting installed packages: {e}")
            return []

    def extract_man_page_text(self, man_file: Path) -> Optional[str]:
        """Extract text from man page (plain or gzipped)."""
        try:
            if man_file.suffix == ".gz":
                with gzip.open(man_file, "rt", encoding="utf-8", errors="ignore") as f:
                    return f.read()
            else:
                with open(man_file, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
        except Exception as e:
            print(f"Error reading {man_file}: {e}")
            return None

    def extract_one_liner(self, man_text: str) -> Optional[str]:
        """Extract one-liner description from man page."""
        lines = man_text.split("\n")
        for i, line in enumerate(lines):
            if "NAME" in line.upper():
                # Look for next non-empty line after NAME
                for j in range(i + 1, min(i + 5, len(lines))):
                    text = lines[j].strip()
                    if text and not text.startswith("."):
                        # Extract text after tool name dash
                        if " - " in text:
                            return text.split(" - ", 1)[1].strip()
                        return text.strip()
        return None

    def extract_syntax(self, man_text: str, tool_name: str) -> Optional[str]:
        """Extract syntax template from man page SYNOPSIS section."""
        lines = man_text.split("\n")
        in_synopsis = False
        syntax_lines = []

        for line in lines:
            if "SYNOPSIS" in line.upper():
                in_synopsis = True
                continue
            if in_synopsis:
                if line and not line.startswith(" ") and not line.startswith("\t"):
                    break
                if line.strip() and not line.startswith("."):
                    syntax_lines.append(line.strip())

        if syntax_lines:
            # Return first non-empty line (usually the command template)
            return syntax_lines[0][:100]  # Limit to 100 chars
        return f"{tool_name} [OPTIONS]"

    def scan_and_populate(self, limit: Optional[int] = None, extract_metadata: bool = True) -> None:
        """Scan packages and populate database."""
        packages = self.get_installed_packages()
        if limit:
            packages = packages[:limit]

        print(f"Found {len(packages)} installed packages")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        inserted = 0
        skipped = 0
        metadata_extractor = MetadataExtractor() if extract_metadata else None

        for i, pkg in enumerate(packages):
            pkg_name = pkg["pkg_name"]
            tool_name = pkg_name.replace("-", "_").replace(".", "_")

            # Skip if already in database
            cursor.execute("SELECT id FROM kali_tools WHERE tool_name = ?", (tool_name,))
            if cursor.fetchone():
                skipped += 1
                continue

            # Look for man page
            man_file = None
            man_text = None
            for man_dir in self.man_paths:
                for ext in [".1.gz", ".1", ".8.gz", ".8", ".5.gz", ".5"]:
                    candidate = Path(man_dir) / f"{pkg_name}{ext}"
                    if candidate.exists():
                        man_file = candidate
                        break
                if man_file:
                    break

            one_liner = None
            syntax_template = f"{pkg_name} [OPTIONS]"

            if man_file:
                man_text = self.extract_man_page_text(man_file)
                if man_text:
                    one_liner = self.extract_one_liner(man_text)
                    syntax_template = self.extract_syntax(man_text, pkg_name)

            # Insert into kali_tools database
            try:
                cursor.execute(
                    """
                    INSERT INTO kali_tools
                    (tool_name, pkg_name, one_line_desc, syntax_template,
                     success_rate, use_count, installed)
                    VALUES (?, ?, ?, ?, 0.5, 0, 1)
                    """,
                    (tool_name, pkg_name, one_liner or "Tool from Kali Linux", syntax_template),
                )
                inserted += 1

                # Extract and store metadata if enabled
                if extract_metadata and metadata_extractor:
                    metadata = metadata_extractor.extract(tool_name, man_text or "")
                    self._store_metadata(cursor, metadata)

            except sqlite3.IntegrityError:
                skipped += 1

            if (i + 1) % 50 == 0:
                print(f"  Processed {i + 1}/{len(packages)}... ({inserted} inserted)")

        conn.commit()
        conn.close()

        print(f"\nScanning complete:")
        print(f"  Inserted: {inserted}")
        print(f"  Skipped: {skipped}")

    def _store_metadata(self, cursor: sqlite3.Cursor, metadata: dict) -> None:
        """Store extracted metadata in tool_metadata table."""
        try:
            cursor.execute(
                """
                INSERT INTO tool_metadata
                (tool_name, execution_type, timeout_seconds, input_method,
                 output_method, output_files_pattern, success_patterns,
                 failure_patterns, parser_type, parser_config, requires_elevated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    metadata.get("tool_name"),
                    metadata.get("execution_type", "one-shot"),
                    metadata.get("timeout_seconds"),
                    metadata.get("input_method", "argv"),
                    metadata.get("output_method", "stdout"),
                    metadata.get("output_files_pattern"),
                    json.dumps(metadata.get("success_patterns", [])),
                    json.dumps(metadata.get("failure_patterns", [])),
                    metadata.get("parser_type", "regex"),
                    json.dumps(metadata.get("parser_config", {})),
                    metadata.get("requires_elevated", False),
                ),
            )
        except sqlite3.IntegrityError:
            # Metadata already exists, skip
            pass


def main() -> None:
    """Main entry point for scanner."""
    import sys

    limit = None
    if len(sys.argv) > 1:
        try:
            limit = int(sys.argv[1])
        except ValueError:
            print("Usage: python -m db.scanner [limit]")
            sys.exit(1)

    scanner = ToolScanner()
    scanner.scan_and_populate(limit=limit)


if __name__ == "__main__":
    main()
