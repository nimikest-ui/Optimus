"""Programmatic extraction of intent, domain, and targets from user prompts."""

import re
import ipaddress
from typing import Optional
from pydantic import BaseModel


class PromptAnalysis(BaseModel):
    """Result of prompt analysis."""

    intent: str  # reconnaissance, enumeration, exploitation, etc.
    domain: str  # ip, domain, cidr, service, web, network, etc.
    targets: list[str]  # parsed target IPs/domains
    raw_prompt: str


class PromptAnalyzer:
    """Analyzes user prompts to extract actionable parameters."""

    # Intent keywords mapped to attack phases
    INTENT_KEYWORDS = {
        "reconnaissance": [
            "scan", "enumerate", "discover", "fingerprint", "identify",
            "probe", "map", "search", "lookup", "investigate",
        ],
        "enumeration": [
            "list", "enumerate", "find", "locate", "identify",
            "discover", "search", "query", "extract",
        ],
        "exploitation": [
            "exploit", "attack", "breach", "compromise", "pwn",
            "hack", "infiltrate", "inject", "execute", "shell",
        ],
        "privilege_escalation": [
            "escalate", "elevate", "privilege", "root", "admin",
            "sudo", "escalation", "priv", "raise",
        ],
        "exfiltration": [
            "extract", "exfiltrate", "steal", "leak", "download",
            "copy", "dump", "grab", "take",
        ],
        "persistence": [
            "persist", "maintain", "keep", "backdoor", "rootkit",
            "permanent", "long-term",
        ],
    }

    # Reverse mapping for quick lookup
    INTENT_BY_KEYWORD = {}
    for intent, keywords in INTENT_KEYWORDS.items():
        for keyword in keywords:
            INTENT_BY_KEYWORD[keyword.lower()] = intent

    def __init__(self):
        pass

    def analyze(self, prompt: str) -> PromptAnalysis:
        """Analyze a user prompt and extract intent, domain, targets."""
        intent = self._extract_intent(prompt)
        domain = self._extract_domain(prompt)
        targets = self._extract_targets(prompt)

        return PromptAnalysis(
            intent=intent,
            domain=domain,
            targets=targets,
            raw_prompt=prompt,
        )

    def _extract_intent(self, prompt: str) -> str:
        """Extract the user's intent from the prompt."""
        prompt_lower = prompt.lower()

        # Check for exact keyword matches
        for keyword, intent in self.INTENT_BY_KEYWORD.items():
            if keyword in prompt_lower:
                return intent

        # Default intents based on patterns
        if any(x in prompt_lower for x in ["port", "service", "version"]):
            return "reconnaissance"
        if any(x in prompt_lower for x in ["user", "password", "credential", "auth"]):
            return "credential_access"
        if any(x in prompt_lower for x in ["vulnerability", "cve", "weakness"]):
            return "exploitation"

        # Default to reconnaissance
        return "reconnaissance"

    def _extract_domain(self, prompt: str) -> str:
        """Infer the domain/target type from the prompt."""
        prompt_lower = prompt.lower()

        # Web-related
        if any(x in prompt_lower for x in ["web", "http", "website", "app", "api", "rest"]):
            return "web"

        # Service/port related
        if any(x in prompt_lower for x in ["port", "service", "socket", "listen"]):
            return "service"

        # Network/IP related
        if any(x in prompt_lower for x in ["network", "subnet", "cidr", "range"]):
            return "network"

        # Database
        if any(x in prompt_lower for x in ["database", "db", "sql", "mysql", "postgres"]):
            return "database"

        # Default to generic network domain
        return "network"

    def _extract_targets(self, prompt: str) -> list[str]:
        """Extract IP addresses, domains, and CIDR ranges from the prompt."""
        targets = []

        # IPv4 addresses and CIDR notation
        ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/\d{1,2})?\b"
        targets.extend(re.findall(ipv4_pattern, prompt))

        # Domain names (basic pattern)
        domain_pattern = r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"
        for match in re.findall(domain_pattern, prompt.lower()):
            # Filter out common false positives
            if not any(x in match for x in ["http://", "https://"]):
                targets.append(match)

        # URLs - extract domain from URLs
        url_pattern = r"(?:https?://)?(?:www\.)?([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)"
        for match in re.findall(url_pattern, prompt.lower()):
            if match not in targets:
                targets.append(match)

        # Remove duplicates while preserving order
        seen = set()
        unique_targets = []
        for target in targets:
            if target.lower() not in seen:
                seen.add(target.lower())
                unique_targets.append(target)

        return unique_targets

    def validate_targets(self, targets: list[str]) -> dict[str, bool]:
        """Validate each target (IP, domain, CIDR)."""
        validation = {}

        for target in targets:
            # Try parsing as IP or CIDR
            try:
                ipaddress.ip_network(target, strict=False)
                validation[target] = True
            except ValueError:
                # Try as a domain (loose validation)
                if re.match(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$", target.lower()):
                    validation[target] = True
                else:
                    validation[target] = False

        return validation
