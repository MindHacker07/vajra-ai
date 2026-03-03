"""
Vajra AI — Nuclei Connector
Integrates with ProjectDiscovery Nuclei — template-based vulnerability scanner.
Requires nuclei CLI installed and accessible in PATH.
"""

import subprocess
import shutil
import json
from connector_manager import BaseConnector


class NucleiConnector(BaseConnector):
    connector_id = "nuclei"
    name = "Nuclei"
    description = "Template-based vulnerability scanner — CVE detection, misconfigurations, exposed panels, default credentials"
    icon = "☢️"
    category = "recon"
    website = "https://github.com/projectdiscovery/nuclei"

    def __init__(self):
        super().__init__()
        self.config = {
            "nuclei_path": "",
            "templates_path": "",
            "rate_limit": "150",
            "concurrency": "25",
        }
        self.actions = [
            {
                "action": "scan",
                "name": "Full Template Scan",
                "description": "Run all nuclei templates against a target",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com"},
                    {"name": "severity", "type": "text", "label": "Severity filter (optional)", "required": False, "placeholder": "critical,high,medium"},
                ],
            },
            {
                "action": "cve_scan",
                "name": "CVE Scan",
                "description": "Scan for known CVEs using nuclei CVE templates",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com"},
                ],
            },
            {
                "action": "misconfig_scan",
                "name": "Misconfiguration Scan",
                "description": "Detect misconfigurations (exposed panels, default creds, etc.)",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com"},
                ],
            },
            {
                "action": "tech_detect",
                "name": "Technology Detection",
                "description": "Detect technologies using nuclei tech-detect templates",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com"},
                ],
            },
            {
                "action": "custom_scan",
                "name": "Custom Template Scan",
                "description": "Run nuclei with custom templates or tags",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com"},
                    {"name": "templates", "type": "text", "label": "Template path or tag", "required": True, "placeholder": "-t cves/ or -tags sqli"},
                    {"name": "extra_args", "type": "text", "label": "Extra arguments", "required": False, "placeholder": "-rate-limit 50"},
                ],
            },
            {
                "action": "scan_list",
                "name": "Scan URL List",
                "description": "Scan multiple targets from a newline-separated list",
                "params": [
                    {"name": "targets", "type": "textarea", "label": "Target URLs (one per line)", "required": True, "placeholder": "https://example1.com\nhttps://example2.com"},
                    {"name": "severity", "type": "text", "label": "Severity filter", "required": False, "placeholder": "critical,high"},
                ],
            },
        ]

    def _nuclei_bin(self):
        custom = self.config.get("nuclei_path", "")
        if custom:
            return custom
        return shutil.which("nuclei") or "nuclei"

    def _run_nuclei(self, args, timeout=600):
        cmd = [self._nuclei_bin()] + args + ["-jsonl", "-silent"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            findings = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

            summary = {}
            for f in findings:
                sev = f.get("info", {}).get("severity", "unknown")
                summary[sev] = summary.get(sev, 0) + 1

            return {
                "status": "completed",
                "total_findings": len(findings),
                "summary": summary,
                "findings": findings[:100],
                "stderr": result.stderr.strip()[:500] if result.stderr else "",
            }
        except FileNotFoundError:
            return {"status": "error", "error": "Nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Scan timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def health_check(self):
        try:
            result = subprocess.run(
                [self._nuclei_bin(), "-version"],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = (result.stdout + result.stderr).strip().split("\n")[0]
            return {"ok": True, "message": output or "Nuclei is available"}
        except FileNotFoundError:
            return {"ok": False, "message": "Nuclei not found in PATH"}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    def execute(self, action, params):
        target = params.get("target", "").strip()
        rl = self.config.get("rate_limit", "150")
        conc = self.config.get("concurrency", "25")
        base_args = ["-rate-limit", rl, "-concurrency", conc]

        if action == "scan":
            if not target:
                return {"status": "error", "error": "Target is required"}
            args = ["-u", target] + base_args
            severity = params.get("severity", "")
            if severity:
                args += ["-severity", severity]
            return self._run_nuclei(args)

        elif action == "cve_scan":
            if not target:
                return {"status": "error", "error": "Target is required"}
            return self._run_nuclei(["-u", target, "-tags", "cve"] + base_args)

        elif action == "misconfig_scan":
            if not target:
                return {"status": "error", "error": "Target is required"}
            return self._run_nuclei(["-u", target, "-tags", "misconfig,exposure,default-login"] + base_args)

        elif action == "tech_detect":
            if not target:
                return {"status": "error", "error": "Target is required"}
            return self._run_nuclei(["-u", target, "-tags", "tech"] + base_args)

        elif action == "custom_scan":
            if not target:
                return {"status": "error", "error": "Target is required"}
            templates = params.get("templates", "").strip()
            extra = params.get("extra_args", "").strip().split()
            args = ["-u", target]
            if templates.startswith("-"):
                args += templates.split()
            else:
                args += ["-t", templates]
            args += base_args + extra
            return self._run_nuclei(args)

        elif action == "scan_list":
            targets_text = params.get("targets", "").strip()
            if not targets_text:
                return {"status": "error", "error": "Targets list is required"}
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write(targets_text)
                tmp_path = f.name
            try:
                args = ["-l", tmp_path] + base_args
                severity = params.get("severity", "")
                if severity:
                    args += ["-severity", severity]
                return self._run_nuclei(args)
            finally:
                os.unlink(tmp_path)

        else:
            return {"status": "error", "error": f"Unknown action: {action}"}
