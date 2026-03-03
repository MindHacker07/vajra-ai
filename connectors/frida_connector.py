"""
Vajra AI — Frida Connector
Integrates with Frida — dynamic instrumentation toolkit for reverse engineering,
hooking, and runtime analysis of mobile/desktop applications.
Requires frida and frida-tools installed (pip install frida frida-tools).
"""

import subprocess
import shutil
import json
from connector_manager import BaseConnector


class FridaConnector(BaseConnector):
    connector_id = "frida"
    name = "Frida"
    description = "Dynamic instrumentation toolkit — hook functions, trace calls, bypass SSL pinning, analyze apps at runtime"
    icon = "🪝"
    category = "mobile"
    website = "https://frida.re/"

    def __init__(self):
        super().__init__()
        self.config = {
            "frida_path": "",
            "device": "",  # empty = default USB device
        }
        self.actions = [
            {
                "action": "list_devices",
                "name": "List Devices",
                "description": "List all Frida-accessible devices (USB, remote, emulators)",
                "params": [],
            },
            {
                "action": "list_apps",
                "name": "List Applications",
                "description": "List installed applications on the target device",
                "params": [
                    {"name": "device", "type": "text", "label": "Device ID (optional)", "required": False, "placeholder": "emulator-5554"},
                ],
            },
            {
                "action": "list_processes",
                "name": "List Running Processes",
                "description": "List currently running processes on the target device",
                "params": [
                    {"name": "device", "type": "text", "label": "Device ID (optional)", "required": False, "placeholder": "emulator-5554"},
                ],
            },
            {
                "action": "run_script",
                "name": "Run Frida Script",
                "description": "Inject and run a Frida JavaScript hook script into a process",
                "params": [
                    {"name": "target", "type": "text", "label": "Target app/PID", "required": True, "placeholder": "com.example.app or 1234"},
                    {"name": "script", "type": "textarea", "label": "Frida JS Script", "required": True, "placeholder": "Java.perform(function() { ... })"},
                    {"name": "device", "type": "text", "label": "Device ID (optional)", "required": False, "placeholder": ""},
                ],
            },
            {
                "action": "ssl_pinning_bypass",
                "name": "SSL Pinning Bypass",
                "description": "Bypass SSL certificate pinning on Android/iOS apps",
                "params": [
                    {"name": "target", "type": "text", "label": "Target app package", "required": True, "placeholder": "com.example.app"},
                    {"name": "device", "type": "text", "label": "Device ID (optional)", "required": False, "placeholder": ""},
                ],
            },
            {
                "action": "trace",
                "name": "Function Tracer",
                "description": "Trace function calls in a running process",
                "params": [
                    {"name": "target", "type": "text", "label": "Target app/PID", "required": True, "placeholder": "com.example.app"},
                    {"name": "pattern", "type": "text", "label": "Function pattern", "required": True, "placeholder": "*!open* or java:com.example.*"},
                    {"name": "device", "type": "text", "label": "Device ID (optional)", "required": False, "placeholder": ""},
                ],
            },
            {
                "action": "spawn",
                "name": "Spawn & Attach",
                "description": "Spawn an app and attach Frida to it from the start",
                "params": [
                    {"name": "target", "type": "text", "label": "Target app package", "required": True, "placeholder": "com.example.app"},
                    {"name": "script_path", "type": "text", "label": "Script file path", "required": False, "placeholder": "/path/to/hook.js"},
                    {"name": "device", "type": "text", "label": "Device ID (optional)", "required": False, "placeholder": ""},
                ],
            },
        ]

    def _frida_bin(self, tool="frida"):
        custom = self.config.get("frida_path", "")
        if custom:
            return custom
        return shutil.which(tool) or tool

    def _device_args(self, params):
        device = params.get("device", "").strip() or self.config.get("device", "")
        if device:
            return ["-D", device]
        return ["-U"]  # default to USB

    def _run_frida_cmd(self, tool, args, timeout=60):
        cmd = [self._frida_bin(tool)] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return {
                "status": "completed",
                "output": result.stdout.strip()[-5000:],
                "errors": result.stderr.strip()[:1000] if result.stderr else "",
            }
        except FileNotFoundError:
            return {"status": "error", "error": f"{tool} not found. Install: pip install frida-tools"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Command timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def health_check(self):
        try:
            result = subprocess.run(
                [self._frida_bin("frida"), "--version"],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            version = result.stdout.strip()
            return {"ok": True, "message": f"Frida v{version}" if version else "Frida is available"}
        except FileNotFoundError:
            return {"ok": False, "message": "Frida not found. Install: pip install frida frida-tools"}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    def execute(self, action, params):
        if action == "list_devices":
            return self._run_frida_cmd("frida-ls-devices", [])

        elif action == "list_apps":
            dev_args = self._device_args(params)
            return self._run_frida_cmd("frida-ps", dev_args + ["-ai"])

        elif action == "list_processes":
            dev_args = self._device_args(params)
            return self._run_frida_cmd("frida-ps", dev_args)

        elif action == "run_script":
            target = params.get("target", "").strip()
            script_code = params.get("script", "").strip()
            if not target or not script_code:
                return {"status": "error", "error": "Target and script are required"}
            dev_args = self._device_args(params)
            # Write script to temp file
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
                f.write(script_code)
                script_path = f.name
            try:
                args = dev_args + ["-l", script_path, target]
                return self._run_frida_cmd("frida", args, timeout=30)
            finally:
                os.unlink(script_path)

        elif action == "ssl_pinning_bypass":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target app package is required"}
            # Universal SSL pinning bypass script
            ssl_bypass_script = """
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.registerClass({
        name: 'vajra.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.getInstance.overload('java.lang.String').implementation = function(type) {
        var c = this.getInstance(type);
        c.init(null, [TrustManager.$new()], null);
        return c;
    };
    console.log('[Vajra] SSL Pinning Bypass Applied');
});
"""
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
                f.write(ssl_bypass_script)
                script_path = f.name
            try:
                dev_args = self._device_args(params)
                args = dev_args + ["-f", target, "-l", script_path, "--no-pause"]
                return self._run_frida_cmd("frida", args, timeout=30)
            finally:
                os.unlink(script_path)

        elif action == "trace":
            target = params.get("target", "").strip()
            pattern = params.get("pattern", "").strip()
            if not target or not pattern:
                return {"status": "error", "error": "Target and pattern are required"}
            dev_args = self._device_args(params)
            args = dev_args + ["-i", pattern, target]
            return self._run_frida_cmd("frida-trace", args, timeout=30)

        elif action == "spawn":
            target = params.get("target", "").strip()
            if not target:
                return {"status": "error", "error": "Target app package is required"}
            dev_args = self._device_args(params)
            args = dev_args + ["-f", target, "--no-pause"]
            script_path = params.get("script_path", "").strip()
            if script_path:
                args += ["-l", script_path]
            return self._run_frida_cmd("frida", args, timeout=30)

        else:
            return {"status": "error", "error": f"Unknown action: {action}"}
