"""
Vajra AI — Security Tool Connector Manager
Manages connections to external security tools (OWASP ZAP, Burp Suite, Nmap,
Nuclei, FFUF, SQLMap, Frida, Android Emulator, Kali Linux tools).
Each connector can be toggled on/off and exposes actions the AI can invoke.
"""

import os
import json
import threading
from datetime import datetime


class ConnectorManager:
    """Central manager for all security-tool connectors."""

    def __init__(self):
        self._connectors: dict[str, "BaseConnector"] = {}
        self._config_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "data", "connectors_config.json"
        )
        self._lock = threading.Lock()
        self._register_builtin_connectors()
        self._load_config()

    # ── Registration ───────────────────────────────────────────────────

    def _register_builtin_connectors(self):
        """Register all built-in security tool connectors."""
        from connectors import (
            OwaspZapConnector,
            BurpSuiteConnector,
            NmapConnector,
            NucleiConnector,
            FfufConnector,
            SqlmapConnector,
            FridaConnector,
            AndroidEmulatorConnector,
            KaliToolsConnector,
        )

        for cls in [
            OwaspZapConnector,
            BurpSuiteConnector,
            NmapConnector,
            NucleiConnector,
            FfufConnector,
            SqlmapConnector,
            FridaConnector,
            AndroidEmulatorConnector,
            KaliToolsConnector,
        ]:
            connector = cls()
            self._connectors[connector.connector_id] = connector

    # ── Persistence ────────────────────────────────────────────────────

    def _load_config(self):
        """Load connector enabled/disabled states and custom settings."""
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, "r") as f:
                    config = json.load(f)
                for cid, cfg in config.get("connectors", {}).items():
                    conn = self._connectors.get(cid)
                    if conn:
                        conn.enabled = cfg.get("enabled", False)
                        conn.config.update(cfg.get("config", {}))
        except Exception:
            pass

    def _save_config(self):
        """Persist connector states."""
        os.makedirs(os.path.dirname(self._config_file), exist_ok=True)
        config = {"connectors": {}}
        for cid, conn in self._connectors.items():
            config["connectors"][cid] = {
                "enabled": conn.enabled,
                "config": conn.config,
            }
        with open(self._config_file, "w") as f:
            json.dump(config, f, indent=2)

    # ── Public API ─────────────────────────────────────────────────────

    def list_connectors(self):
        """Return serialisable list of all connectors with status."""
        result = []
        for conn in self._connectors.values():
            result.append(conn.to_dict())
        return result

    def get_connector(self, connector_id):
        return self._connectors.get(connector_id)

    def toggle_connector(self, connector_id, enabled: bool):
        """Enable or disable a connector and persist."""
        conn = self._connectors.get(connector_id)
        if not conn:
            return None
        conn.enabled = enabled
        if not enabled:
            conn.status = "disabled"
        else:
            conn.status = "enabled"
        self._save_config()
        return conn.to_dict()

    def update_connector_config(self, connector_id, new_config: dict):
        """Update connector-specific settings (host, port, api_key, …)."""
        conn = self._connectors.get(connector_id)
        if not conn:
            return None
        conn.config.update(new_config)
        self._save_config()
        return conn.to_dict()

    def health_check(self, connector_id):
        """Run a health-check / connectivity test for one connector."""
        conn = self._connectors.get(connector_id)
        if not conn:
            return {"error": "Connector not found"}
        return conn.health_check()

    def health_check_all(self):
        """Run health checks for all enabled connectors."""
        results = {}
        for cid, conn in self._connectors.items():
            if conn.enabled:
                results[cid] = conn.health_check()
        return results

    def execute(self, connector_id, action, params=None):
        """Execute an action on a connector."""
        conn = self._connectors.get(connector_id)
        if not conn:
            return {"error": f"Connector '{connector_id}' not found"}
        if not conn.enabled:
            return {"error": f"Connector '{conn.name}' is disabled. Enable it first."}
        return conn.execute(action, params or {})

    def get_all_actions(self):
        """Return a flat list of actions from all *enabled* connectors."""
        actions = []
        for conn in self._connectors.values():
            if conn.enabled:
                for action in conn.actions:
                    actions.append({
                        **action,
                        "connector_id": conn.connector_id,
                        "connector_name": conn.name,
                    })
        return actions

    def shutdown(self):
        """Graceful shutdown."""
        for conn in self._connectors.values():
            try:
                conn.cleanup()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════
#  BASE CONNECTOR
# ═══════════════════════════════════════════════════════════════════════

class BaseConnector:
    """Abstract base class every tool connector inherits from."""

    connector_id: str = ""
    name: str = ""
    description: str = ""
    icon: str = ""
    category: str = ""          # "web_pentest", "network", "mobile", "exploitation", "fuzzing", "recon", "framework"
    website: str = ""

    def __init__(self):
        self.enabled: bool = False
        self.status: str = "disabled"   # disabled | enabled | connected | error
        self.config: dict = {}          # overridable per-tool settings
        self.actions: list[dict] = []   # filled in subclass __init__

    def to_dict(self):
        return {
            "connector_id": self.connector_id,
            "name": self.name,
            "description": self.description,
            "icon": self.icon,
            "category": self.category,
            "website": self.website,
            "enabled": self.enabled,
            "status": self.status,
            "config": self._safe_config(),
            "actions": self.actions,
        }

    def _safe_config(self):
        """Return config with sensitive values masked."""
        safe = {}
        for k, v in self.config.items():
            if any(s in k.lower() for s in ("key", "secret", "password", "token")):
                safe[k] = "***" if v else ""
            else:
                safe[k] = v
        return safe

    # ── Subclass interface ─────────────────────────────────────────────

    def health_check(self) -> dict:
        """Check if the tool is reachable / installed. Return dict with 'ok' bool."""
        raise NotImplementedError

    def execute(self, action: str, params: dict) -> dict:
        """Execute a named action with given params. Return result dict."""
        raise NotImplementedError

    def cleanup(self):
        """Optional teardown."""
        pass
