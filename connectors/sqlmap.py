"""
Vajra AI — SQLMap Connector
Integrates with SQLMap — automatic SQL injection detection and exploitation tool.
Requires sqlmap (Python-based) installed and accessible.
"""

import subprocess
import shutil
import json
import os
import tempfile
from connector_manager import BaseConnector


class SqlmapConnector(BaseConnector):
    connector_id = "sqlmap"
    name = "SQLMap"
    description = "Automatic SQL injection detection & exploitation — database enumeration, data extraction, OS shell access"
    icon = "💉"
    category = "exploitation"
    website = "https://sqlmap.org/"

    def __init__(self):
        super().__init__()
        self.config = {
            "sqlmap_path": "",  # path to sqlmap.py or sqlmap binary
            "python_path": "",  # python interpreter if needed
            "default_level": "1",
            "default_risk": "1",
            "tamper_scripts": "",
        }
        self.actions = [
            {
                "action": "test_injection",
                "name": "Test for SQL Injection",
                "description": "Test a URL parameter for SQL injection vulnerabilities",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL with parameter", "required": True, "placeholder": "https://example.com/page?id=1"},
                    {"name": "level", "type": "text", "label": "Level (1-5)", "required": False, "placeholder": "1"},
                    {"name": "risk", "type": "text", "label": "Risk (1-3)", "required": False, "placeholder": "1"},
                ],
            },
            {
                "action": "dump_database",
                "name": "Dump Database",
                "description": "Extract database tables and data from a vulnerable endpoint",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com/page?id=1"},
                    {"name": "database", "type": "text", "label": "Database name (optional)", "required": False, "placeholder": ""},
                    {"name": "table", "type": "text", "label": "Table name (optional)", "required": False, "placeholder": ""},
                ],
            },
            {
                "action": "enumerate_dbs",
                "name": "Enumerate Databases",
                "description": "List all databases on the target DBMS",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com/page?id=1"},
                ],
            },
            {
                "action": "enumerate_tables",
                "name": "Enumerate Tables",
                "description": "List tables in a specific database",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com/page?id=1"},
                    {"name": "database", "type": "text", "label": "Database name", "required": True, "placeholder": "webapp_db"},
                ],
            },
            {
                "action": "post_injection",
                "name": "POST Parameter Injection",
                "description": "Test POST parameters for SQL injection",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com/login"},
                    {"name": "data", "type": "text", "label": "POST data", "required": True, "placeholder": "username=admin&password=test"},
                    {"name": "parameter", "type": "text", "label": "Parameter to test", "required": False, "placeholder": "username"},
                ],
            },
            {
                "action": "cookie_injection",
                "name": "Cookie Injection",
                "description": "Test cookie parameters for SQL injection",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com/dashboard"},
                    {"name": "cookie", "type": "text", "label": "Cookie string", "required": True, "placeholder": "session=abc123; user_id=1*"},
                ],
            },
            {
                "action": "custom_scan",
                "name": "Custom SQLMap Scan",
                "description": "Run sqlmap with custom arguments",
                "params": [
                    {"name": "arguments", "type": "text", "label": "SQLMap arguments", "required": True, "placeholder": "-u 'http://example.com/?id=1' --batch --dbs"},
                ],
            },
        ]

    def _sqlmap_cmd(self):
        """Build the sqlmap command."""
        custom = self.config.get("sqlmap_path", "")
        if custom:
            if custom.endswith(".py"):
                python = self.config.get("python_path", "") or "python3"
                return [python, custom]
            return [custom]
        # Try to find sqlmap in PATH
        found = shutil.which("sqlmap")
        if found:
            return [found]
        return ["sqlmap"]

    def _run_sqlmap(self, args, timeout=300):
        """Execute sqlmap and return output."""
        cmd = self._sqlmap_cmd() + args + ["--batch", "--output-dir", tempfile.mkdtemp(prefix="vajra_sqlmap_")]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = result.stdout.strip()
            errors = result.stderr.strip()

            # Parse key findings from output
            findings = self._parse_output(output)

            return {
                "status": "completed",
                "findings": findings,
                "raw_output": output[-5000:] if len(output) > 5000 else output,
                "errors": errors[:1000] if errors else "",
            }
        except FileNotFoundError:
            return {"status": "error", "error": "SQLMap not found. Install: pip install sqlmap"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "SQLMap scan timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _parse_output(self, output):
        """Extract structured findings from sqlmap output."""
        findings = {
            "injectable": False,
            "dbms": "",
            "injection_types": [],
            "databases": [],
            "tables": [],
            "data": [],
        }

        lines = output.split("\n")
        for line in lines:
            line_lower = line.strip().lower()
            if "is vulnerable" in line_lower or "injectable" in line_lower:
                findings["injectable"] = True
            if "back-end dbms" in line_lower:
                findings["dbms"] = line.split(":")[-1].strip() if ":" in line else ""
            if "type:" in line_lower and ("boolean" in line_lower or "time" in line_lower or "union" in line_lower or "error" in line_lower or "stacked" in line_lower):
                findings["injection_types"].append(line.strip())
            if "available databases" in line_lower:
                # Next lines are database names
                pass
            if line.strip().startswith("[*] "):
                val = line.strip()[4:]
                if val and val not in findings["databases"]:
                    findings["databases"].append(val)

        return findings

    def health_check(self):
        try:
            result = subprocess.run(
                self._sqlmap_cmd() + ["--version"],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = (result.stdout + result.stderr).strip().split("\n")[0]
            return {"ok": True, "message": output or "SQLMap is available"}
        except FileNotFoundError:
            return {"ok": False, "message": "SQLMap not found. Install: pip install sqlmap"}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    def execute(self, action, params):
        target = params.get("target", "").strip()
        level = params.get("level", "") or self.config.get("default_level", "1")
        risk = params.get("risk", "") or self.config.get("default_risk", "1")
        tamper = self.config.get("tamper_scripts", "")
        base_args = ["--level", level, "--risk", risk]
        if tamper:
            base_args += ["--tamper", tamper]

        if action == "test_injection":
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            args = ["-u", target] + base_args
            return self._run_sqlmap(args)

        elif action == "dump_database":
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            args = ["-u", target, "--dump"] + base_args
            db = params.get("database", "")
            table = params.get("table", "")
            if db:
                args += ["-D", db]
            if table:
                args += ["-T", table]
            return self._run_sqlmap(args, timeout=600)

        elif action == "enumerate_dbs":
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            return self._run_sqlmap(["-u", target, "--dbs"] + base_args)

        elif action == "enumerate_tables":
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            db = params.get("database", "")
            if not db:
                return {"status": "error", "error": "Database name is required"}
            return self._run_sqlmap(["-u", target, "-D", db, "--tables"] + base_args)

        elif action == "post_injection":
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            data = params.get("data", "")
            if not data:
                return {"status": "error", "error": "POST data is required"}
            args = ["-u", target, "--data", data] + base_args
            parameter = params.get("parameter", "")
            if parameter:
                args += ["-p", parameter]
            return self._run_sqlmap(args)

        elif action == "cookie_injection":
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            cookie = params.get("cookie", "")
            if not cookie:
                return {"status": "error", "error": "Cookie string is required"}
            return self._run_sqlmap(["-u", target, "--cookie", cookie, "--level", "2"] + base_args)

        elif action == "custom_scan":
            arguments = params.get("arguments", "").strip().split()
            if not arguments:
                return {"status": "error", "error": "Arguments are required"}
            return self._run_sqlmap(arguments)

        else:
            return {"status": "error", "error": f"Unknown action: {action}"}
