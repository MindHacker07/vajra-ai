"""
Vajra AI — OWASP ZAP Connector
Integrates with OWASP ZAP proxy/scanner via its REST API.
ZAP must be running with the API enabled (default: http://localhost:8080).
"""

import json
import urllib.request
import urllib.parse
import urllib.error
from connector_manager import BaseConnector


class OwaspZapConnector(BaseConnector):
    connector_id = "owasp_zap"
    name = "OWASP ZAP"
    description = "Web application security scanner — automated scanning, spidering, active/passive scan, and API testing"
    icon = "🔶"
    category = "web_pentest"
    website = "https://www.zaproxy.org/"

    def __init__(self):
        super().__init__()
        self.config = {
            "host": "http://localhost",
            "port": "8080",
            "api_key": "",
        }
        self.actions = [
            {
                "action": "spider_scan",
                "name": "Spider Scan",
                "description": "Crawl a target URL to discover all pages and endpoints",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com"},
                    {"name": "max_depth", "type": "text", "label": "Max Depth", "required": False, "placeholder": "5"},
                ],
            },
            {
                "action": "active_scan",
                "name": "Active Scan",
                "description": "Run active vulnerability scan against a target (intrusive)",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com"},
                    {"name": "policy", "type": "text", "label": "Scan Policy", "required": False, "placeholder": "Default Policy"},
                ],
            },
            {
                "action": "passive_scan",
                "name": "Get Passive Scan Alerts",
                "description": "Retrieve alerts found by passive scanning (non-intrusive)",
                "params": [
                    {"name": "base_url", "type": "text", "label": "Base URL filter", "required": False, "placeholder": "https://example.com"},
                ],
            },
            {
                "action": "get_alerts",
                "name": "Get Alerts",
                "description": "Get all alerts/findings from ZAP for a target",
                "params": [
                    {"name": "base_url", "type": "text", "label": "Base URL filter", "required": False, "placeholder": "https://example.com"},
                    {"name": "risk_level", "type": "text", "label": "Min Risk (0-3)", "required": False, "placeholder": "0"},
                ],
            },
            {
                "action": "ajax_spider",
                "name": "AJAX Spider",
                "description": "Crawl JavaScript-heavy applications using a headless browser",
                "params": [
                    {"name": "target", "type": "text", "label": "Target URL", "required": True, "placeholder": "https://example.com"},
                ],
            },
            {
                "action": "generate_report",
                "name": "Generate Report",
                "description": "Generate an HTML security report from ZAP findings",
                "params": [],
            },
        ]

    def _api_url(self, path):
        host = self.config.get("host", "http://localhost").rstrip("/")
        port = self.config.get("port", "8080")
        api_key = self.config.get("api_key", "")
        sep = "&" if "?" in path else "?"
        key_param = f"{sep}apikey={api_key}" if api_key else ""
        return f"{host}:{port}{path}{key_param}"

    def _api_get(self, path, timeout=30):
        url = self._api_url(path)
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise ConnectionError(f"ZAP API unreachable: {e}")
        except Exception as e:
            raise RuntimeError(f"ZAP API error: {e}")

    def health_check(self):
        try:
            data = self._api_get("/JSON/core/view/version/")
            return {
                "ok": True,
                "version": data.get("version", "unknown"),
                "message": f"ZAP v{data.get('version', '?')} is running",
            }
        except Exception as e:
            return {"ok": False, "message": str(e)}

    def execute(self, action, params):
        try:
            if action == "spider_scan":
                return self._spider_scan(params)
            elif action == "active_scan":
                return self._active_scan(params)
            elif action == "passive_scan":
                return self._passive_scan(params)
            elif action == "get_alerts":
                return self._get_alerts(params)
            elif action == "ajax_spider":
                return self._ajax_spider(params)
            elif action == "generate_report":
                return self._generate_report(params)
            else:
                return {"status": "error", "error": f"Unknown action: {action}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _spider_scan(self, params):
        target = params.get("target", "")
        if not target:
            return {"status": "error", "error": "Target URL is required"}
        target_enc = urllib.parse.quote(target, safe="")
        data = self._api_get(f"/JSON/spider/action/scan/?url={target_enc}")
        scan_id = data.get("scan")
        return {
            "status": "started",
            "scan_id": scan_id,
            "message": f"Spider scan started on {target} (scan_id={scan_id})",
        }

    def _active_scan(self, params):
        target = params.get("target", "")
        if not target:
            return {"status": "error", "error": "Target URL is required"}
        target_enc = urllib.parse.quote(target, safe="")
        data = self._api_get(f"/JSON/ascan/action/scan/?url={target_enc}")
        scan_id = data.get("scan")
        return {
            "status": "started",
            "scan_id": scan_id,
            "message": f"Active scan started on {target} (scan_id={scan_id})",
        }

    def _passive_scan(self, params):
        records = self._api_get("/JSON/pscan/view/recordsToScan/")
        return {
            "status": "completed",
            "records_to_scan": records.get("recordsToScan", 0),
        }

    def _get_alerts(self, params):
        base_url = params.get("base_url", "")
        path = "/JSON/core/view/alerts/"
        if base_url:
            path += f"?baseurl={urllib.parse.quote(base_url, safe='')}"
        data = self._api_get(path)
        alerts = data.get("alerts", [])
        summary = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for a in alerts:
            risk = a.get("risk", "Informational")
            summary[risk] = summary.get(risk, 0) + 1
        return {
            "status": "completed",
            "total_alerts": len(alerts),
            "summary": summary,
            "alerts": alerts[:50],  # cap to avoid huge payloads
        }

    def _ajax_spider(self, params):
        target = params.get("target", "")
        if not target:
            return {"status": "error", "error": "Target URL is required"}
        target_enc = urllib.parse.quote(target, safe="")
        self._api_get(f"/JSON/ajaxSpider/action/scan/?url={target_enc}")
        return {
            "status": "started",
            "message": f"AJAX spider started on {target}",
        }

    def _generate_report(self, _params):
        data = self._api_get("/OTHER/core/other/htmlreport/")
        return {
            "status": "completed",
            "message": "HTML report generated",
            "report_preview": str(data)[:2000] if data else "No data",
        }
