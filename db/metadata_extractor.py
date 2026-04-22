"""Extract execution/parsing metadata from tool man pages and names."""

import re
import json
from typing import Optional, Dict, Any


class MetadataExtractor:
    """Extracts execution metadata from tool names and man pages."""

    # Tool categories for timeout defaults
    TIMEOUT_DEFAULTS = {
        "port_scanner": 120,  # nmap, masscan
        "password_cracker": 300,  # hashcat, john, aircrack
        "web_scanner": 300,  # nikto, sqlmap, gobuster
        "packet_capture": 30,  # tcpdump, tshark, airodump
        "network_tool": 10,  # dig, nslookup, whois
        "generic": 60,  # default fallback
    }

    # Keywords that indicate execution type
    LONG_RUNNING_KEYWORDS = [
        "crack", "hash", "brute", "monitor", "capture", "sniff",
        "indefinitely", "continuously", "until", "running",
        "listener", "server", "daemon", "background",
    ]

    ONE_SHOT_KEYWORDS = [
        "scan", "enum", "fingerprint", "check", "find",
        "probe", "query", "fetch", "print", "output",
        "report", "complete", "finish", "done",
    ]

    # Output format detection
    OUTPUT_FILE_FLAGS = ["-o", "-w", "--output", "--write", "-f", "--file"]

    def __init__(self):
        pass

    def extract(self, tool_name: str, man_text: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract metadata from tool name and man page.

        Returns dict with keys:
        - execution_type: one-shot | long-running
        - timeout_seconds: int or None
        - input_method: argv | stdin | file | interface
        - output_method: stdout | file | files | side-effect
        - output_files_pattern: regex pattern (if file output)
        - success_patterns: list of regex patterns
        - failure_patterns: list of regex patterns
        - parser_type: string
        - requires_elevated: bool
        """
        metadata = {
            "tool_name": tool_name,
            "execution_type": self._infer_execution_type(tool_name, man_text or ""),
            "input_method": self._infer_input_method(tool_name, man_text or ""),
            "output_method": self._infer_output_method(tool_name, man_text or ""),
            "parser_type": self._infer_parser_type(tool_name, man_text or ""),
            "requires_elevated": self._infer_elevated_requirement(tool_name),
        }

        # Set timeout based on execution type and category
        metadata["timeout_seconds"] = self._get_timeout(tool_name, metadata["execution_type"])

        # Extract output file pattern if applicable
        if metadata["output_method"] in ["file", "files"]:
            metadata["output_files_pattern"] = self._extract_output_pattern(man_text or "")

        # Infer success/failure patterns
        metadata["success_patterns"] = self._infer_success_patterns(tool_name)
        metadata["failure_patterns"] = self._infer_failure_patterns(tool_name)

        # Parser config
        metadata["parser_config"] = self._get_parser_config(tool_name, metadata["parser_type"])

        return metadata

    def _infer_execution_type(self, tool_name: str, man_text: str) -> str:
        """Infer execution type from tool name and man page."""
        tool_lower = tool_name.lower()
        man_lower = man_text.lower()

        # Check for long-running keywords
        for keyword in self.LONG_RUNNING_KEYWORDS:
            if keyword in tool_lower or keyword in man_lower:
                return "long-running"

        # Check for one-shot keywords
        for keyword in self.ONE_SHOT_KEYWORDS:
            if keyword in tool_lower or keyword in man_lower:
                return "one-shot"

        # Default to one-shot (safe assumption)
        return "one-shot"

    def _infer_input_method(self, tool_name: str, man_text: str) -> str:
        """Infer input method from tool name and man page."""
        man_lower = man_text.lower()

        # Check for interface input (network tools)
        if any(x in tool_name.lower() for x in ["air", "dump", "mon", "capture"]):
            return "interface"

        # Check for stdin
        if "stdin" in man_lower or "reads from standard input" in man_lower:
            return "stdin"

        # Check for file input
        if any(x in man_lower for x in ["input file", "capture file", "wordlist"]):
            return "file"

        # Default to argv
        return "argv"

    def _infer_output_method(self, tool_name: str, man_text: str) -> str:
        """Infer output method from man page."""
        man_lower = man_text.lower()
        synopsis = self._extract_synopsis(man_text)

        # Check for file output flags
        if any(flag in synopsis for flag in self.OUTPUT_FILE_FLAGS):
            # Check if multiple files (patterns like -01.csv, -02.csv)
            if "-01" in man_text or "-02" in man_text:
                return "files"
            return "file"

        # Check for explicit "writes to" mentions
        if any(x in man_lower for x in ["writes to file", "creates file", "output file"]):
            return "file"

        # Check for side-effect tools
        if any(x in tool_name.lower() for x in ["aireplay", "iptables", "modprobe"]):
            return "side-effect"

        # Default to stdout
        return "stdout"

    def _infer_parser_type(self, tool_name: str, man_text: str) -> str:
        """Infer parser type from tool."""
        tool_lower = tool_name.lower()

        # Specific mappings
        if tool_lower == "nmap":
            return "nmap_xml"
        elif "airodump" in tool_lower:
            return "csv_networks"
        elif "aircrack" in tool_lower:
            return "aircrack_stdout"
        elif any(x in tool_lower for x in ["hashcat", "john"]):
            return "cracker_stdout"
        elif any(x in tool_lower for x in ["csv", "gobuster"]):
            return "plain_text"

        # Default fallback
        return "regex"

    def _infer_elevated_requirement(self, tool_name: str) -> bool:
        """Check if tool typically requires elevated privileges."""
        tool_lower = tool_name.lower()
        elevated_tools = [
            "airmon", "aireplay", "aircrack", "tcpdump", "iptables",
            "ifconfig", "iwconfig", "monitor", "sniffer", "packet",
        ]
        return any(x in tool_lower for x in elevated_tools)

    def _get_timeout(self, tool_name: str, execution_type: str) -> Optional[int]:
        """Get reasonable timeout for tool."""
        if execution_type == "one-shot":
            # Most one-shot tools finish quickly
            if any(x in tool_name.lower() for x in ["scan", "nmap", "masscan"]):
                return 120
            else:
                return 60

        # Long-running tools
        if any(x in tool_name.lower() for x in ["crack", "hash"]):
            return 300  # Password cracking can take longer
        elif any(x in tool_name.lower() for x in ["capture", "dump", "sniff"]):
            return 30  # Capture tools run briefly
        else:
            return 60  # Default

    def _extract_synopsis(self, man_text: str) -> str:
        """Extract SYNOPSIS section from man page."""
        lines = man_text.split("\n")
        synopsis_lines = []
        in_synopsis = False

        for line in lines:
            if "SYNOPSIS" in line.upper():
                in_synopsis = True
                continue
            if in_synopsis:
                if line and not line.startswith(" ") and not line.startswith("\t"):
                    break
                if line.strip():
                    synopsis_lines.append(line)

        return " ".join(synopsis_lines)

    def _extract_output_pattern(self, man_text: str) -> Optional[str]:
        """Extract output file pattern from man page."""
        # Look for patterns like -01.csv, *.txt, etc.
        patterns = re.findall(r"-\d+\.\w+|\*\.\w+", man_text)
        if patterns:
            return patterns[0]

        # Check for common output flags
        if "-w" in man_text:
            return "-*.csv"  # Common for airodump-ng
        if "-o" in man_text:
            return "*.txt"  # Common default

        return None

    def _infer_success_patterns(self, tool_name: str) -> list:
        """Infer success patterns for tool type."""
        tool_lower = tool_name.lower()

        if any(x in tool_lower for x in ["crack", "hash"]):
            return [
                r"[Kk]ey found!.*",
                r"[Pp]assword found!.*",
                r"Success",
            ]
        elif any(x in tool_lower for x in ["scan", "nmap"]):
            return [
                r"Nmap done.*",
                r"Host is up",
            ]
        elif any(x in tool_lower for x in ["capture", "dump"]):
            return [
                r"\d+ packets captured",
                r"packets found",
            ]
        else:
            return []

    def _infer_failure_patterns(self, tool_name: str) -> list:
        """Infer failure patterns for tool type."""
        tool_lower = tool_name.lower()

        if any(x in tool_lower for x in ["crack"]):
            return [
                r"[Nn]o password found",
                r"[Ff]ailed",
            ]
        else:
            return []

    def _get_parser_config(self, tool_name: str, parser_type: str) -> Dict[str, Any]:
        """Get parser-specific configuration."""
        if parser_type == "nmap_xml":
            return {
                "output_format": "xml",
                "extract_hosts": True,
                "extract_ports": True,
                "extract_services": True,
            }
        elif parser_type == "csv_networks":
            return {
                "file_pattern": "-01.csv",
                "csv_format": "bssid,first_seen,last_seen,channel,speed,privacy,cipher,auth,power,beacons,ivs,lan_ip,id_length,ssid",
                "extract_all": True,
                "key_columns": ["bssid", "ssid", "channel", "power", "privacy"],
            }
        elif parser_type == "aircrack_stdout":
            return {
                "extract_password_regex": r"Key found! \[(.*?)\]",
                "extract_progress_regex": r"\[(\d+)%\]",
            }
        else:
            return {}
