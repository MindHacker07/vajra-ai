"""
Vajra AI — FFUF Connector
Integrates with FFUF — fast web fuzzer for directory/file discovery, parameter fuzzing, vhost discovery.
Requires ffuf CLI installed and accessible in PATH.
"""

import subprocess
import shutil
import json
import os
import tempfile
from connector_manager import BaseConnector


class FfufConnector(BaseConnector):
    connector_id = "ffuf"
    name = "FFUF"
    description = "Fast web fuzzer — directory brute-force, parameter fuzzing, vhost discovery, content discovery"
    icon = "⚡"
    category = "fuzzing"
    website = "https://github.com/ffuf/ffuf"

    def __init__(self):
        super().__init__()
        self.config = {
            "ffuf_path": "",
            "wordlist_dir": "",
            "default_wordlist": "",
            "threads": "40",
            "rate_limit": "0",
        }
        self.actions = [
            {
                "action": "dir_fuzz",
                "name": "Directory Fuzzing",
                "description": "Fuzz for directories and files on a web server",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com/FUZZ"},
                    {"name": "wordlist", "type": "text", "label": "Wordlist path", "required": False, "placeholder": "/usr/share/wordlists/dirb/common.txt"},
                    {"name": "extensions", "type": "text", "label": "Extensions", "required": False, "placeholder": ".php,.html,.js,.txt"},
                    {"name": "filter_code", "type": "text", "label": "Filter status codes", "required": False, "placeholder": "404,403"},
                ],
            },
            {
                "action": "vhost_fuzz",
                "name": "Virtual Host Fuzzing",
                "description": "Discover virtual hosts on a target server",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "http://target.com"},
                    {"name": "wordlist", "type": "text", "label": "Wordlist path", "required": False, "placeholder": "/usr/share/wordlists/subdomains.txt"},
                    {"name": "filter_size", "type": "text", "label": "Filter response size", "required": False, "placeholder": "1234"},
                ],
            },
            {
                "action": "param_fuzz",
                "name": "Parameter Fuzzing",
                "description": "Fuzz GET/POST parameters to find hidden parameters",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com/api?FUZZ=test"},
                    {"name": "wordlist", "type": "text", "label": "Wordlist path", "required": False, "placeholder": "/usr/share/wordlists/params.txt"},
                    {"name": "method", "type": "text", "label": "HTTP Method", "required": False, "placeholder": "GET"},
                ],
            },
            {
                "action": "subdomain_fuzz",
                "name": "Subdomain Fuzzing",
                "description": "Discover subdomains by fuzzing DNS names",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://FUZZ.example.com"},
                    {"name": "wordlist", "type": "text", "label": "Wordlist path", "required": False, "placeholder": "/usr/share/wordlists/subdomains-top1million-5000.txt"},
                ],
            },
            {
                "action": "custom_fuzz",
                "name": "Custom Fuzz",
                "description": "Run ffuf with custom arguments",
                "params": [
                    {"name": "arguments", "type": "text", "label": "Full ffuf arguments", "required": True, "placeholder": "-u https://example.com/FUZZ -w wordlist.txt -mc 200"},
                ],
            },
        ]

    def _ffuf_bin(self):
        custom = self.config.get("ffuf_path", "")
        if custom:
            return custom
        return shutil.which("ffuf") or "ffuf"

    def _default_wordlist(self):
        """Return a default wordlist path."""
        custom = self.config.get("default_wordlist", "")
        if custom and os.path.exists(custom):
            return custom
        # Common locations
        for path in [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ]:
            if os.path.exists(path):
                return path
        return ""

    def _run_ffuf(self, args, timeout=300):
        """Run ffuf and parse JSON output."""
        # Write output to temp file
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_file = f.name

        try:
            cmd = [self._ffuf_bin()] + args + ["-o", output_file, "-of", "json", "-silent"]
            threads = self.config.get("threads", "40")
            rate = self.config.get("rate_limit", "0")
            if "-t" not in args:
                cmd += ["-t", threads]
            if rate and rate != "0" and "-rate" not in " ".join(args):
                cmd += ["-rate", rate]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

            # Parse JSON output
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, "r") as f:
                    data = json.load(f)
                results_list = data.get("results", [])
                return {
                    "status": "completed",
                    "total_results": len(results_list),
                    "results": [
                        {
                            "input": r.get("input", {}).get("FUZZ", ""),
                            "url": r.get("url", ""),
                            "status": r.get("status", 0),
                            "length": r.get("length", 0),
                            "words": r.get("words", 0),
                            "lines": r.get("lines", 0),
                            "content_type": r.get("content-type", ""),
                            "redirect_location": r.get("redirectlocation", ""),
                        }
                        for r in results_list[:200]
                    ],
                    "command_line": data.get("commandline", ""),
                }
            else:
                return {
                    "status": "completed",
                    "total_results": 0,
                    "results": [],
                    "stderr": result.stderr.strip()[:500] if result.stderr else "",
                }
        except FileNotFoundError:
            return {"status": "error", "error": "ffuf not found. Install: go install github.com/ffuf/ffuf/v2@latest"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Fuzzing timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

    def health_check(self):
        try:
            result = subprocess.run(
                [self._ffuf_bin(), "-V"],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = (result.stdout + result.stderr).strip().split("\n")[0]
            return {"ok": True, "message": output or "ffuf is available"}
        except FileNotFoundError:
            return {"ok": False, "message": "ffuf not found in PATH"}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    def execute(self, action, params):
        if action == "dir_fuzz":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            if "FUZZ" not in target:
                target = target.rstrip("/") + "/FUZZ"
            wordlist = params.get("wordlist", "").strip() or self._default_wordlist()
            if not wordlist:
                return {"status": "error", "error": "No wordlist specified and no default found"}
            args = ["-u", target, "-w", wordlist]
            extensions = params.get("extensions", "")
            if extensions:
                args += ["-e", extensions]
            filter_code = params.get("filter_code", "")
            if filter_code:
                args += ["-fc", filter_code]
            return self._run_ffuf(args)

        elif action == "vhost_fuzz":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            wordlist = params.get("wordlist", "").strip() or self._default_wordlist()
            if not wordlist:
                return {"status": "error", "error": "No wordlist specified"}
            args = ["-u", target, "-w", wordlist, "-H", "Host: FUZZ.target.com"]
            fs = params.get("filter_size", "")
            if fs:
                args += ["-fs", fs]
            return self._run_ffuf(args)

        elif action == "param_fuzz":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            wordlist = params.get("wordlist", "").strip() or self._default_wordlist()
            if not wordlist:
                return {"status": "error", "error": "No wordlist specified"}
            method = params.get("method", "GET").upper()
            args = ["-u", target, "-w", wordlist, "-X", method]
            return self._run_ffuf(args)

        elif action == "subdomain_fuzz":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target URL is required"}
            wordlist = params.get("wordlist", "").strip() or self._default_wordlist()
            if not wordlist:
                return {"status": "error", "error": "No wordlist specified"}
            args = ["-u", target, "-w", wordlist]
            return self._run_ffuf(args)

        elif action == "custom_fuzz":
            arguments = params.get("arguments", "").strip().split()
            if not arguments:
                return {"status": "error", "error": "Arguments are required"}
            return self._run_ffuf(arguments)

        else:
            return {"status": "error", "error": f"Unknown action: {action}"}
