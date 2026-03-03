"""
Vajra AI — Nmap Connector
Wraps the Nmap CLI for advanced network scanning.
Requires nmap to be installed and accessible in PATH.
"""

import subprocess
import shutil
import json
import re
import xml.etree.ElementTree as ET
from connector_manager import BaseConnector


class NmapConnector(BaseConnector):
    connector_id = "nmap"
    name = "Nmap"
    description = "Network exploration and security auditing — host discovery, port scanning, service/OS detection, NSE scripts"
    icon = "🗺️"
    category = "network"
    website = "https://nmap.org/"

    def __init__(self):
        super().__init__()
        self.config = {
            "nmap_path": "",  # empty = auto-detect in PATH
            "default_timing": "T3",
        }
        self.actions = [
            {
                "action": "quick_scan",
                "name": "Quick Scan",
                "description": "Fast scan of top 100 ports with service detection (-sV --top-ports 100)",
                "params": [
                    {"name": "target", "type": "text", "label": "Target (IP/CIDR/hostname)", "required": True, "placeholder": "192.168.1.0/24"},
                ],
            },
            {
                "action": "full_scan",
                "name": "Full Port Scan",
                "description": "Scan all 65535 TCP ports with service & OS detection (-sS -sV -O -p-)",
                "params": [
                    {"name": "target", "type": "text", "label": "Target", "required": True, "placeholder": "192.168.1.1"},
                ],
            },
            {
                "action": "vuln_scan",
                "name": "Vulnerability Scan",
                "description": "Run Nmap NSE vulnerability scripts (--script vuln)",
                "params": [
                    {"name": "target", "type": "text", "label": "Target", "required": True, "placeholder": "192.168.1.1"},
                    {"name": "ports", "type": "text", "label": "Ports (optional)", "required": False, "placeholder": "80,443,8080"},
                ],
            },
            {
                "action": "host_discovery",
                "name": "Host Discovery",
                "description": "Discover live hosts on a network (-sn ping scan)",
                "params": [
                    {"name": "target", "type": "text", "label": "Network (CIDR)", "required": True, "placeholder": "192.168.1.0/24"},
                ],
            },
            {
                "action": "custom_scan",
                "name": "Custom Scan",
                "description": "Run nmap with custom arguments",
                "params": [
                    {"name": "target", "type": "text", "label": "Target", "required": True, "placeholder": "192.168.1.1"},
                    {"name": "arguments", "type": "text", "label": "Nmap arguments", "required": True, "placeholder": "-sS -sV -p 1-1024 --script default"},
                ],
            },
            {
                "action": "script_scan",
                "name": "NSE Script Scan",
                "description": "Run specific NSE scripts against a target",
                "params": [
                    {"name": "target", "type": "text", "label": "Target", "required": True, "placeholder": "192.168.1.1"},
                    {"name": "scripts", "type": "text", "label": "Scripts", "required": True, "placeholder": "http-title,http-headers,ssl-cert"},
                    {"name": "ports", "type": "text", "label": "Ports (optional)", "required": False, "placeholder": "80,443"},
                ],
            },
        ]

    def _nmap_bin(self):
        custom = self.config.get("nmap_path", "")
        if custom:
            return custom
        return shutil.which("nmap") or "nmap"

    def _run_nmap(self, args, timeout=300):
        """Execute nmap and return parsed output."""
        cmd = [self._nmap_bin()] + args + ["-oX", "-"]  # XML output to stdout
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode not in (0, 1):  # 1 = some hosts down, still valid
                return {"status": "error", "error": result.stderr.strip() or "Nmap returned error"}
            return self._parse_xml(result.stdout)
        except FileNotFoundError:
            return {"status": "error", "error": "Nmap not found. Install it from https://nmap.org/"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Scan timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _parse_xml(self, xml_str):
        """Parse nmap XML output into a structured dict."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return {"status": "completed", "raw_output": xml_str[:3000]}

        hosts = []
        for host_el in root.findall("host"):
            host_data = {"status": "up", "addresses": [], "ports": [], "os": [], "hostnames": []}

            # Status
            status = host_el.find("status")
            if status is not None:
                host_data["status"] = status.get("state", "unknown")

            # Addresses
            for addr in host_el.findall("address"):
                host_data["addresses"].append({
                    "addr": addr.get("addr"),
                    "type": addr.get("addrtype"),
                })

            # Hostnames
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    host_data["hostnames"].append(hn.get("name", ""))

            # Ports
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    port_data = {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                    }
                    state = port.find("state")
                    if state is not None:
                        port_data["state"] = state.get("state", "unknown")
                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = service.get("name", "")
                        port_data["product"] = service.get("product", "")
                        port_data["version"] = service.get("version", "")
                        port_data["extra_info"] = service.get("extrainfo", "")
                    # Scripts
                    scripts = []
                    for script in port.findall("script"):
                        scripts.append({
                            "id": script.get("id", ""),
                            "output": script.get("output", "")[:500],
                        })
                    if scripts:
                        port_data["scripts"] = scripts
                    host_data["ports"].append(port_data)

            # OS detection
            os_el = host_el.find("os")
            if os_el is not None:
                for osmatch in os_el.findall("osmatch"):
                    host_data["os"].append({
                        "name": osmatch.get("name", ""),
                        "accuracy": osmatch.get("accuracy", ""),
                    })

            hosts.append(host_data)

        scan_info = root.find("scaninfo")
        run_stats = root.find("runstats/finished")

        return {
            "status": "completed",
            "scan_type": scan_info.get("type", "") if scan_info is not None else "",
            "hosts": hosts,
            "total_hosts": len(hosts),
            "elapsed": run_stats.get("elapsed", "") if run_stats is not None else "",
        }

    def health_check(self):
        try:
            result = subprocess.run(
                [self._nmap_bin(), "--version"],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            version_line = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
            return {"ok": True, "message": version_line}
        except FileNotFoundError:
            return {"ok": False, "message": "Nmap not found in PATH. Install from https://nmap.org/"}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    def execute(self, action, params):
        target = params.get("target", "").strip()
        timing = self.config.get("default_timing", "T3")

        if action in ("quick_scan", "full_scan", "vuln_scan", "host_discovery", "custom_scan", "script_scan"):
            if not target:
                return {"status": "error", "error": "Target is required"}

        if action == "quick_scan":
            return self._run_nmap(["-sV", "--top-ports", "100", f"-{timing}", target])
        elif action == "full_scan":
            return self._run_nmap(["-sS", "-sV", "-O", "-p-", f"-{timing}", target], timeout=600)
        elif action == "vuln_scan":
            ports = params.get("ports", "")
            args = ["--script", "vuln", f"-{timing}", target]
            if ports:
                args = ["-p", ports] + args
            return self._run_nmap(args, timeout=600)
        elif action == "host_discovery":
            return self._run_nmap(["-sn", target])
        elif action == "custom_scan":
            arguments = params.get("arguments", "").strip().split()
            return self._run_nmap(arguments + [target], timeout=600)
        elif action == "script_scan":
            scripts = params.get("scripts", "default")
            ports = params.get("ports", "")
            args = ["--script", scripts, target]
            if ports:
                args = ["-p", ports] + args
            return self._run_nmap(args)
        else:
            return {"status": "error", "error": f"Unknown action: {action}"}
