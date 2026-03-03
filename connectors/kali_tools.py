"""
Vajra AI — Kali Linux Tools Connector
Integrates with common Kali Linux penetration testing tools.
Provides a unified interface to popular tools: metasploit, hydra, john,
hashcat, wpscan, nikto, gobuster, enum4linux, smbclient, etc.
Requires the respective tools installed (e.g. on Kali Linux or manually).
"""

import subprocess
import shutil
from connector_manager import BaseConnector


class KaliToolsConnector(BaseConnector):
    connector_id = "kali_tools"
    name = "Kali Linux Tools"
    description = "Collection of Kali Linux security tools — Metasploit, Hydra, John, Nikto, WPScan, Gobuster, enum4linux and more"
    icon = "🐉"
    category = "framework"
    website = "https://www.kali.org/tools/"

    def __init__(self):
        super().__init__()
        self.config = {
            "tools_prefix": "",  # optional path prefix for tools
        }
        self.actions = [
            {
                "action": "nikto_scan",
                "name": "Nikto Web Scan",
                "description": "Run Nikto web server scanner for vulnerabilities and misconfigurations",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL/host", "required": True, "placeholder": "https://example.com"},
                    {"name": "extra_args", "type": "text", "label": "Extra arguments", "required": False, "placeholder": "-Tuning 1 2 3"},
                ],
            },
            {
                "action": "hydra_attack",
                "name": "Hydra Brute Force",
                "description": "Run Hydra password brute-force against a service",
                "params": [
                    {"name": "target", "type": "text", "label": "Target host", "required": True, "placeholder": "192.168.1.1"},
                    {"name": "service", "type": "text", "label": "Service", "required": True, "placeholder": "ssh, ftp, http-post-form, smb, rdp"},
                    {"name": "username", "type": "text", "label": "Username or file", "required": True, "placeholder": "admin or /path/to/users.txt"},
                    {"name": "password_list", "type": "text", "label": "Password list path", "required": True, "placeholder": "/usr/share/wordlists/rockyou.txt"},
                    {"name": "extra_args", "type": "text", "label": "Extra arguments", "required": False, "placeholder": "-t 4 -vV"},
                ],
            },
            {
                "action": "john_crack",
                "name": "John the Ripper",
                "description": "Crack password hashes with John the Ripper",
                "params": [
                    {"name": "hash_file", "type": "text", "label": "Hash file path", "required": True, "placeholder": "/path/to/hashes.txt"},
                    {"name": "format", "type": "text", "label": "Hash format (optional)", "required": False, "placeholder": "raw-md5, bcrypt, ntlm"},
                    {"name": "wordlist", "type": "text", "label": "Wordlist (optional)", "required": False, "placeholder": "/usr/share/wordlists/rockyou.txt"},
                ],
            },
            {
                "action": "wpscan",
                "name": "WPScan",
                "description": "WordPress vulnerability scanner",
                "params": [
                    {"name": "target", "type": "text", "label": "WordPress URL", "required": True, "placeholder": "https://example.com"},
                    {"name": "api_token", "type": "text", "label": "WPScan API token (optional)", "required": False, "placeholder": ""},
                    {"name": "enumerate", "type": "text", "label": "Enumerate (optional)", "required": False, "placeholder": "vp,vt,u1-20"},
                ],
            },
            {
                "action": "gobuster",
                "name": "Gobuster",
                "description": "Directory/DNS/vhost brute-force with Gobuster",
                "params": [
                    {"name": "mode", "type": "text", "label": "Mode", "required": True, "placeholder": "dir, dns, vhost"},
                    {"name": "target", "type": "text", "label": "Target URL/domain", "required": True, "placeholder": "https://example.com"},
                    {"name": "wordlist", "type": "text", "label": "Wordlist path", "required": True, "placeholder": "/usr/share/wordlists/dirb/common.txt"},
                    {"name": "extra_args", "type": "text", "label": "Extra arguments", "required": False, "placeholder": "-x php,html -t 50"},
                ],
            },
            {
                "action": "enum4linux",
                "name": "Enum4linux",
                "description": "Enumerate SMB/Windows information from a target",
                "params": [
                    {"name": "target", "type": "text", "label": "Target IP", "required": True, "placeholder": "192.168.1.1"},
                    {"name": "options", "type": "text", "label": "Options", "required": False, "placeholder": "-a (all enumeration)"},
                ],
            },
            {
                "action": "whatweb",
                "name": "WhatWeb",
                "description": "Web technology fingerprinting tool",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com"},
                    {"name": "aggression", "type": "text", "label": "Aggression level (1-4)", "required": False, "placeholder": "1"},
                ],
            },
            {
                "action": "amass_enum",
                "name": "Amass Subdomain Enum",
                "description": "Subdomain enumeration using OWASP Amass",
                "params": [
                    {"name": "domain", "type": "text", "label": "Target domain", "required": True, "placeholder": "example.com"},
                    {"name": "passive", "type": "text", "label": "Passive only (yes/no)", "required": False, "placeholder": "yes"},
                ],
            },
            {
                "action": "msfconsole",
                "name": "Metasploit Command",
                "description": "Execute a Metasploit command via msfconsole",
                "params": [
                    {"name": "command", "type": "text", "label": "MSF command", "required": True, "placeholder": "search type:exploit platform:windows smb"},
                    {"name": "extra_args", "type": "text", "label": "Extra arguments", "required": False, "placeholder": ""},
                ],
            },
            {
                "action": "searchsploit",
                "name": "SearchSploit",
                "description": "Search ExploitDB for exploits and shellcodes",
                "params": [
                    {"name": "query", "type": "text", "label": "Search query", "required": True, "placeholder": "Apache 2.4.49"},
                    {"name": "extra_args", "type": "text", "label": "Extra arguments", "required": False, "placeholder": "--json -w"},
                ],
            },
            {
                "action": "custom_tool",
                "name": "Run Custom Tool",
                "description": "Execute any Kali tool by command",
                "params": [
                    {"name": "command", "type": "text", "label": "Full command", "required": True, "placeholder": "whatweb --aggression=3 example.com"},
                ],
            },
        ]

    def _tool_path(self, tool):
        prefix = self.config.get("tools_prefix", "")
        if prefix:
            import os
            candidate = os.path.join(prefix, tool)
            if os.path.exists(candidate):
                return candidate
        return shutil.which(tool) or tool

    def _run_tool(self, tool, args, timeout=300):
        cmd = [self._tool_path(tool)] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return {
                "status": "completed",
                "output": result.stdout.strip()[-8000:],
                "errors": result.stderr.strip()[:1000] if result.stderr else "",
                "return_code": result.returncode,
            }
        except FileNotFoundError:
            return {"status": "error", "error": f"{tool} not found. Install it or ensure it's in PATH."}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": f"{tool} timed out after {timeout}s"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def health_check(self):
        """Check availability of common Kali tools."""
        tools_to_check = ["nmap", "nikto", "hydra", "john", "gobuster", "wpscan", "searchsploit", "whatweb"]
        available = []
        missing = []
        for t in tools_to_check:
            if shutil.which(t) or shutil.which(self._tool_path(t)):
                available.append(t)
            else:
                missing.append(t)
        ok = len(available) > 0
        msg_parts = []
        if available:
            msg_parts.append(f"Available: {', '.join(available)}")
        if missing:
            msg_parts.append(f"Missing: {', '.join(missing)}")
        return {"ok": ok, "message": " | ".join(msg_parts), "available": available, "missing": missing}

    def execute(self, action, params):
        if action == "nikto_scan":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target is required"}
            args = ["-host", target, "-Display", "1234EP"]
            extra = params.get("extra_args", "").strip()
            if extra:
                args += extra.split()
            return self._run_tool("nikto", args, timeout=600)

        elif action == "hydra_attack":
            target = params.get("target", "").strip()
            service = params.get("service", "").strip()
            username = params.get("username", "").strip()
            pw_list = params.get("password_list", "").strip()
            if not all([target, service, username, pw_list]):
                return {"status": "error", "error": "Target, service, username, and password list are required"}
            # Determine if username is a file or single user
            import os
            if os.path.isfile(username):
                user_arg = ["-L", username]
            else:
                user_arg = ["-l", username]
            args = user_arg + ["-P", pw_list, target, service]
            extra = params.get("extra_args", "").strip()
            if extra:
                args += extra.split()
            return self._run_tool("hydra", args, timeout=600)

        elif action == "john_crack":
            hash_file = params.get("hash_file", "").strip()
            if not hash_file:
                return {"status": "error", "error": "Hash file is required"}
            args = [hash_file]
            fmt = params.get("format", "").strip()
            if fmt:
                args += [f"--format={fmt}"]
            wordlist = params.get("wordlist", "").strip()
            if wordlist:
                args += [f"--wordlist={wordlist}"]
            return self._run_tool("john", args, timeout=600)

        elif action == "wpscan":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target is required"}
            args = ["--url", target, "--no-banner"]
            token = params.get("api_token", "").strip()
            if token:
                args += ["--api-token", token]
            enum = params.get("enumerate", "").strip()
            if enum:
                args += ["-e", enum]
            return self._run_tool("wpscan", args, timeout=600)

        elif action == "gobuster":
            mode = params.get("mode", "dir").strip()
            target = params.get("target", "").strip()
            wordlist = params.get("wordlist", "").strip()
            if not target or not wordlist:
                return {"status": "error", "error": "Target and wordlist are required"}
            args = [mode, "-u", target, "-w", wordlist]
            extra = params.get("extra_args", "").strip()
            if extra:
                args += extra.split()
            return self._run_tool("gobuster", args, timeout=300)

        elif action == "enum4linux":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target is required"}
            options = params.get("options", "-a").strip()
            args = options.split() + [target]
            return self._run_tool("enum4linux", args)

        elif action == "whatweb":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target is required"}
            args = [target]
            agg = params.get("aggression", "1").strip()
            if agg:
                args += [f"--aggression={agg}"]
            return self._run_tool("whatweb", args)

        elif action == "amass_enum":
            domain = params.get("domain", "").strip()
            if not domain:
                return {"status": "error", "error": "Domain is required"}
            args = ["enum", "-d", domain]
            passive = params.get("passive", "").strip().lower()
            if passive in ("yes", "true", "1"):
                args.append("-passive")
            return self._run_tool("amass", args, timeout=600)

        elif action == "msfconsole":
            command = params.get("command", "").strip()
            if not command:
                return {"status": "error", "error": "MSF command is required"}
            args = ["-q", "-x", f"{command}; exit"]
            return self._run_tool("msfconsole", args, timeout=120)

        elif action == "searchsploit":
            query = params.get("query", "").strip()
            if not query:
                return {"status": "error", "error": "Search query is required"}
            args = query.split()
            extra = params.get("extra_args", "").strip()
            if extra:
                args += extra.split()
            return self._run_tool("searchsploit", args, timeout=30)

        elif action == "custom_tool":
            command = params.get("command", "").strip()
            if not command:
                return {"status": "error", "error": "Command is required"}
            parts = command.split()
            tool = parts[0]
            args = parts[1:] if len(parts) > 1 else []
            return self._run_tool(tool, args, timeout=300)

        else:
            return {"status": "error", "error": f"Unknown action: {action}"}
