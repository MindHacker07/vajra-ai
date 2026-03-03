"""
Vajra AI — Android Emulator Connector
Integrates with Android Emulator / ADB for mobile security testing.
Requires Android SDK with adb and emulator in PATH.
"""

import subprocess
import shutil
import re
from connector_manager import BaseConnector


class AndroidEmulatorConnector(BaseConnector):
    connector_id = "android_emulator"
    name = "Android Emulator"
    description = "Android emulator & ADB integration — app install, logcat, screen capture, root shell, APK analysis"
    icon = "📱"
    category = "mobile"
    website = "https://developer.android.com/studio/run/emulator"

    def __init__(self):
        super().__init__()
        self.config = {
            "adb_path": "",
            "emulator_path": "",
            "device_serial": "",  # e.g. emulator-5554
        }
        self.actions = [
            {
                "action": "list_devices",
                "name": "List Devices",
                "description": "List connected Android devices and emulators",
                "params": [],
            },
            {
                "action": "list_avds",
                "name": "List AVDs",
                "description": "List available Android Virtual Devices",
                "params": [],
            },
            {
                "action": "start_emulator",
                "name": "Start Emulator",
                "description": "Launch an Android emulator AVD",
                "params": [
                    {"name": "avd_name", "type": "text", "label": "AVD Name", "required": True, "placeholder": "Pixel_6_API_33"},
                    {"name": "writable_system", "type": "text", "label": "Writable system (yes/no)", "required": False, "placeholder": "no"},
                ],
            },
            {
                "action": "install_apk",
                "name": "Install APK",
                "description": "Install an APK on the connected device/emulator",
                "params": [
                    {"name": "apk_path", "type": "text", "label": "APK file path", "required": True, "placeholder": "/path/to/app.apk"},
                    {"name": "device", "type": "text", "label": "Device serial (optional)", "required": False, "placeholder": "emulator-5554"},
                ],
            },
            {
                "action": "list_packages",
                "name": "List Packages",
                "description": "List installed packages on the device",
                "params": [
                    {"name": "filter", "type": "text", "label": "Package filter (optional)", "required": False, "placeholder": "com.example"},
                    {"name": "device", "type": "text", "label": "Device serial (optional)", "required": False, "placeholder": "emulator-5554"},
                ],
            },
            {
                "action": "pull_apk",
                "name": "Pull APK",
                "description": "Extract an installed app's APK from the device",
                "params": [
                    {"name": "package", "type": "text", "label": "Package name", "required": True, "placeholder": "com.example.app"},
                    {"name": "output_path", "type": "text", "label": "Output path", "required": False, "placeholder": "./extracted.apk"},
                    {"name": "device", "type": "text", "label": "Device serial (optional)", "required": False, "placeholder": ""},
                ],
            },
            {
                "action": "logcat",
                "name": "Logcat",
                "description": "Capture device logcat output (filtered)",
                "params": [
                    {"name": "filter", "type": "text", "label": "Logcat filter", "required": False, "placeholder": "*:E or com.example.app"},
                    {"name": "lines", "type": "text", "label": "Number of lines", "required": False, "placeholder": "100"},
                    {"name": "device", "type": "text", "label": "Device serial (optional)", "required": False, "placeholder": ""},
                ],
            },
            {
                "action": "shell",
                "name": "ADB Shell Command",
                "description": "Execute a shell command on the device via ADB",
                "params": [
                    {"name": "command", "type": "text", "label": "Shell command", "required": True, "placeholder": "pm list packages -3"},
                    {"name": "device", "type": "text", "label": "Device serial (optional)", "required": False, "placeholder": ""},
                ],
            },
            {
                "action": "screenshot",
                "name": "Screenshot",
                "description": "Capture a screenshot from the device",
                "params": [
                    {"name": "output_path", "type": "text", "label": "Output path", "required": False, "placeholder": "./screenshot.png"},
                    {"name": "device", "type": "text", "label": "Device serial (optional)", "required": False, "placeholder": ""},
                ],
            },
            {
                "action": "proxy_setup",
                "name": "Setup Proxy",
                "description": "Configure the device to use a proxy (for Burp/ZAP interception)",
                "params": [
                    {"name": "proxy_host", "type": "text", "label": "Proxy host", "required": True, "placeholder": "10.0.2.2"},
                    {"name": "proxy_port", "type": "text", "label": "Proxy port", "required": True, "placeholder": "8080"},
                    {"name": "device", "type": "text", "label": "Device serial (optional)", "required": False, "placeholder": ""},
                ],
            },
        ]

    def _adb_bin(self):
        custom = self.config.get("adb_path", "")
        if custom:
            return custom
        return shutil.which("adb") or "adb"

    def _emulator_bin(self):
        custom = self.config.get("emulator_path", "")
        if custom:
            return custom
        return shutil.which("emulator") or "emulator"

    def _device_args(self, params):
        device = params.get("device", "").strip() or self.config.get("device_serial", "")
        if device:
            return ["-s", device]
        return []

    def _run_adb(self, args, timeout=30):
        cmd = [self._adb_bin()] + args
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
            return {"status": "error", "error": "ADB not found. Install Android SDK Platform Tools."}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "ADB command timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def health_check(self):
        try:
            result = subprocess.run(
                [self._adb_bin(), "version"],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            version = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
            return {"ok": True, "message": version}
        except FileNotFoundError:
            return {"ok": False, "message": "ADB not found. Install Android SDK Platform Tools."}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    def execute(self, action, params):
        if action == "list_devices":
            return self._run_adb(["devices", "-l"])

        elif action == "list_avds":
            try:
                result = subprocess.run(
                    [self._emulator_bin(), "-list-avds"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                avds = [a.strip() for a in result.stdout.strip().split("\n") if a.strip()]
                return {"status": "completed", "avds": avds}
            except FileNotFoundError:
                return {"status": "error", "error": "Android emulator not found"}
            except Exception as e:
                return {"status": "error", "error": str(e)}

        elif action == "start_emulator":
            avd = params.get("avd_name", "").strip()
            if not avd:
                return {"status": "error", "error": "AVD name is required"}
            args = [self._emulator_bin(), "-avd", avd]
            writable = params.get("writable_system", "").lower()
            if writable in ("yes", "true", "1"):
                args.append("-writable-system")
            try:
                subprocess.Popen(
                    args,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                return {"status": "started", "message": f"Emulator {avd} is starting..."}
            except Exception as e:
                return {"status": "error", "error": str(e)}

        elif action == "install_apk":
            apk = params.get("apk_path", "").strip()
            if not apk:
                return {"status": "error", "error": "APK path is required"}
            dev = self._device_args(params)
            return self._run_adb(dev + ["install", "-r", apk], timeout=60)

        elif action == "list_packages":
            dev = self._device_args(params)
            pkg_filter = params.get("filter", "").strip()
            result = self._run_adb(dev + ["shell", "pm", "list", "packages", "-f"])
            if result.get("status") == "completed" and pkg_filter:
                lines = result["output"].split("\n")
                result["output"] = "\n".join(l for l in lines if pkg_filter.lower() in l.lower())
            return result

        elif action == "pull_apk":
            package = params.get("package", "").strip()
            if not package:
                return {"status": "error", "error": "Package name is required"}
            dev = self._device_args(params)
            # Get APK path
            path_result = self._run_adb(dev + ["shell", "pm", "path", package])
            if path_result.get("status") != "completed":
                return path_result
            apk_path_on_device = path_result["output"].replace("package:", "").strip()
            output = params.get("output_path", "").strip() or f"./{package}.apk"
            return self._run_adb(dev + ["pull", apk_path_on_device, output], timeout=60)

        elif action == "logcat":
            dev = self._device_args(params)
            lines = params.get("lines", "100").strip()
            log_filter = params.get("filter", "").strip()
            args = dev + ["logcat", "-d", "-t", lines]
            if log_filter:
                args.append(log_filter)
            return self._run_adb(args, timeout=30)

        elif action == "shell":
            cmd = params.get("command", "").strip()
            if not cmd:
                return {"status": "error", "error": "Shell command is required"}
            dev = self._device_args(params)
            return self._run_adb(dev + ["shell"] + cmd.split(), timeout=30)

        elif action == "screenshot":
            dev = self._device_args(params)
            output = params.get("output_path", "").strip() or "./screenshot.png"
            # Capture on device then pull
            self._run_adb(dev + ["shell", "screencap", "-p", "/sdcard/vajra_screen.png"])
            result = self._run_adb(dev + ["pull", "/sdcard/vajra_screen.png", output])
            self._run_adb(dev + ["shell", "rm", "/sdcard/vajra_screen.png"])
            if result.get("status") == "completed":
                result["message"] = f"Screenshot saved to {output}"
            return result

        elif action == "proxy_setup":
            host = params.get("proxy_host", "").strip()
            port = params.get("proxy_port", "").strip()
            if not host or not port:
                return {"status": "error", "error": "Proxy host and port are required"}
            dev = self._device_args(params)
            result = self._run_adb(dev + ["shell", "settings", "put", "global", "http_proxy", f"{host}:{port}"])
            if result.get("status") == "completed":
                result["message"] = f"Proxy set to {host}:{port}"
            return result

        else:
            return {"status": "error", "error": f"Unknown action: {action}"}
