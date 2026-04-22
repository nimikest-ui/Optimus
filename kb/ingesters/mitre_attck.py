"""MITRE ATT&CK mapping for Kali tools to attack phases."""

import sqlite3
from typing import Optional


# Heuristic mapping of tool patterns to MITRE ATT&CK phases
TOOL_PHASE_MAPPING = {
    # Reconnaissance (passive info gathering)
    "reconnaissance": [
        "dig", "host", "whois", "nslookup", "shodan", "zoomeye",
        "censys", "passive", "osint", "recon",
    ],
    # Resource Development
    "resource-development": [
        "hashcat", "john", "aircrack", "hydra", "medusa",
    ],
    # Initial Access
    "initial-access": [
        "searchsploit", "exploit", "shellcode", "payload", "msfvenom",
        "sqlmap", "xssstrike", "commix", "wpscan", "joomla",
    ],
    # Execution
    "execution": [
        "python", "ruby", "perl", "bash", "sh", "nc", "netcat",
        "socat", "telnet", "ssh", "rsh", "metasploit",
    ],
    # Persistence
    "persistence": [
        "backdoor", "rootkit", "cron", "at", "persistence",
    ],
    # Privilege Escalation
    "privilege-escalation": [
        "sudo", "su", "getuid", "setuid", "cve", "exploit",
        "privesc", "uac", "bypass",
    ],
    # Defense Evasion
    "defense-evasion": [
        "antivirus", "firewall", "ids", "ips", "evasion", "obfuscate",
        "encode", "encrypt", "bypass", "stealth",
    ],
    # Credential Access
    "credential-access": [
        "hashcat", "john", "hydra", "medusa", "ophcrack",
        "mimikatz", "secretsdump", "pass", "crack", "keylogger",
        "sniffer", "tcpdump", "wireshark", "ettercap",
    ],
    # Discovery (active probing for services, ports, resources)
    "discovery": [
        "nmap", "nessus", "openvas", "masscan", "zmap", "scan",
        "port", "probe", "enum", "gobuster", "dirbuster", "dirb", "ffuf", "wfuzz",
        "nikto", "wafw00f", "whatweb", "masscan", "zmap", "amap", "hping",
        "tcpdump", "wireshark", "ettercap", "sniff",
    ],
    # Lateral Movement
    "lateral-movement": [
        "psexec", "smbclient", "smbmap", "rpcclient", "impacket",
        "evil", "responder", "mimikatz", "ssh", "rdp",
    ],
    # Collection
    "collection": [
        "sniff", "tcpdump", "wireshark", "tshark", "ettercap",
        "keylogger", "screenshot", "audio", "video", "screen",
    ],
    # Command and Control
    "command-and-control": [
        "metasploit", "empire", "cobalt", "beacon", "c2",
        "listener", "agent", "reverse", "shell", "meterpreter",
    ],
    # Exfiltration
    "exfiltration": [
        "exfil", "steal", "leak", "download", "upload", "ftp", "sftp", "scp", "curl", "wget",
    ],
    # Impact
    "impact": [
        "delete", "wipe", "encrypt", "ransomware", "DoS", "denial",
        "defacement", "destruction",
    ],
}

# Reverse mapping for quick lookup
PHASE_BY_KEYWORD = {}
for phase, keywords in TOOL_PHASE_MAPPING.items():
    for keyword in keywords:
        PHASE_BY_KEYWORD[keyword.lower()] = phase


class MitreIngestor:
    """Maps Kali tools to MITRE ATT&CK attack phases."""

    def __init__(self, db_path: str = "kali_tools.db"):
        self.db_path = db_path

    def infer_phase(self, tool_name: str, description: str = "") -> Optional[str]:
        """Infer attack phase from tool name and description."""
        tool_lower = tool_name.lower()
        desc_lower = description.lower() if description else ""

        # Check tool name exact matches first
        if tool_lower in PHASE_BY_KEYWORD:
            return PHASE_BY_KEYWORD[tool_lower]

        # Check for substring matches in keywords
        for keyword, phase in PHASE_BY_KEYWORD.items():
            if keyword in tool_lower:
                return phase

        # Check description for keywords
        for keyword, phase in PHASE_BY_KEYWORD.items():
            if keyword in desc_lower:
                return phase

        # Default to reconnaissance for unknown tools with network characteristics
        if any(x in tool_lower for x in ["scan", "probe", "sniff", "spy", "monitor"]):
            return "reconnaissance"

        return "unknown"

    def update_tool_phases(self) -> None:
        """Update attack_phase column for all tools based on heuristics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get all tools without assigned phases
        cursor.execute("SELECT id, tool_name, one_line_desc FROM kali_tools WHERE attack_phase IS NULL")
        tools = cursor.fetchall()

        print(f"Found {len(tools)} tools without assigned phases")

        updated = 0
        for i, (tool_id, tool_name, description) in enumerate(tools):
            phase = self.infer_phase(tool_name, description or "")
            cursor.execute("UPDATE kali_tools SET attack_phase = ? WHERE id = ?", (phase, tool_id))
            updated += 1

            if (i + 1) % 500 == 0:
                print(f"  Processed {i + 1}/{len(tools)}...")

        conn.commit()
        conn.close()

        print(f"\nPhase assignment complete: {updated} tools updated")

        # Print summary stats
        self._print_phase_summary()

    def _print_phase_summary(self) -> None:
        """Print summary of tools by attack phase."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT attack_phase, COUNT(*) as count
            FROM kali_tools
            GROUP BY attack_phase
            ORDER BY count DESC
            """
        )

        print("\nTools by attack phase:")
        for phase, count in cursor.fetchall():
            print(f"  {phase or 'unknown'}: {count}")

        conn.close()


def main() -> None:
    """Main entry point for MITRE ingester."""
    ingestor = MitreIngestor()
    ingestor.update_tool_phases()


if __name__ == "__main__":
    main()
