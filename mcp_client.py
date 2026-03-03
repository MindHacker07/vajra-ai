"""
Vajra AI - MCP (Model Context Protocol) Client
Manages connections to MCP servers and tool execution.
"""

import os
import json
import subprocess
import threading
import time
import uuid
import sys
from datetime import datetime


class MCPServer:
    """Represents a single MCP server connection."""

    def __init__(self, name, transport, command=None, url=None, args=None, env=None):
        self.id = str(uuid.uuid4())[:8]
        self.name = name
        self.transport = transport  # "stdio" or "sse"
        self.command = command
        self.url = url
        self.args = args or []
        self.env = env or {}
        self.status = "disconnected"  # disconnected, connecting, connected, error
        self.tools = []
        self.resources = []
        self.process = None
        self._request_id = 0
        self._pending = {}
        self._reader_thread = None
        self._lock = threading.Lock()
        self.error_message = None

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "transport": self.transport,
            "command": self.command,
            "url": self.url,
            "args": self.args,
            "env": {k: "***" for k in self.env},  # Hide env values
            "status": self.status,
            "tools": self.tools,
            "resources": self.resources,
            "error": self.error_message,
        }

    def connect(self):
        """Connect to the MCP server."""
        if self.transport == "stdio":
            return self._connect_stdio()
        elif self.transport == "sse":
            return self._connect_sse()
        return False

    def _connect_stdio(self):
        """Connect via stdio transport."""
        try:
            self.status = "connecting"
            self.error_message = None

            # Build the command
            cmd_parts = self.command.split() if isinstance(self.command, str) else [self.command]
            cmd_parts.extend(self.args)

            # Merge environment
            env = os.environ.copy()
            env.update(self.env)

            self.process = subprocess.Popen(
                cmd_parts,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                bufsize=0,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )

            # Start reader thread
            self._reader_thread = threading.Thread(target=self._read_stdout, daemon=True)
            self._reader_thread.start()

            # Initialize the MCP protocol
            init_result = self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "vajra-ai",
                    "version": "1.0.0"
                }
            })

            if init_result and not init_result.get("error"):
                # Send initialized notification
                self._send_notification("notifications/initialized", {})

                # List tools
                tools_result = self._send_request("tools/list", {})
                if tools_result and "tools" in tools_result.get("result", {}):
                    self.tools = [
                        {
                            "name": t["name"],
                            "description": t.get("description", ""),
                            "inputSchema": t.get("inputSchema", {}),
                        }
                        for t in tools_result["result"]["tools"]
                    ]

                # List resources
                try:
                    res_result = self._send_request("resources/list", {})
                    if res_result and "resources" in res_result.get("result", {}):
                        self.resources = [
                            {
                                "uri": r["uri"],
                                "name": r.get("name", ""),
                                "description": r.get("description", ""),
                            }
                            for r in res_result["result"]["resources"]
                        ]
                except Exception:
                    pass  # Server may not support resources

                self.status = "connected"
                return True
            else:
                error = init_result.get("error", {}).get("message", "Unknown error") if init_result else "No response"
                self.status = "error"
                self.error_message = f"Init failed: {error}"
                return False

        except FileNotFoundError:
            self.status = "error"
            self.error_message = f"Command not found: {self.command}"
            return False
        except Exception as e:
            self.status = "error"
            self.error_message = str(e)
            return False

    def _connect_sse(self):
        """Connect via SSE transport (simplified — stores URL for proxy use)."""
        try:
            self.status = "connecting"
            self.error_message = None

            # For SSE, we validate the URL and mark as connected
            # Actual SSE communication happens per-request
            if not self.url:
                self.status = "error"
                self.error_message = "No URL provided"
                return False

            import urllib.request
            req = urllib.request.Request(self.url, method="GET")
            req.add_header("Accept", "text/event-stream")

            # Just check if server is reachable
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                resp.close()
            except Exception:
                pass  # SSE servers may not respond to simple GET

            self.status = "connected"
            self.tools = []
            self.resources = []
            return True

        except Exception as e:
            self.status = "error"
            self.error_message = str(e)
            return False

    def _read_stdout(self):
        """Read from process stdout in a background thread."""
        try:
            while self.process and self.process.poll() is None:
                line = self.process.stdout.readline()
                if not line:
                    break
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    msg_id = msg.get("id")
                    if msg_id and msg_id in self._pending:
                        self._pending[msg_id] = msg
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    def _send_request(self, method, params, timeout=10):
        """Send a JSON-RPC request and wait for response."""
        with self._lock:
            self._request_id += 1
            req_id = self._request_id

        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }

        self._pending[req_id] = None

        try:
            data = json.dumps(request) + "\n"
            self.process.stdin.write(data.encode("utf-8"))
            self.process.stdin.flush()
        except Exception as e:
            del self._pending[req_id]
            return {"error": {"message": str(e)}}

        # Wait for response
        start = time.time()
        while time.time() - start < timeout:
            if self._pending.get(req_id) is not None:
                result = self._pending.pop(req_id)
                return result
            time.sleep(0.05)

        self._pending.pop(req_id, None)
        return {"error": {"message": "Timeout waiting for response"}}

    def _send_notification(self, method, params):
        """Send a JSON-RPC notification (no response expected)."""
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        try:
            data = json.dumps(notification) + "\n"
            self.process.stdin.write(data.encode("utf-8"))
            self.process.stdin.flush()
        except Exception:
            pass

    def call_tool(self, tool_name, arguments=None):
        """Call a tool on this MCP server."""
        if self.status != "connected":
            return {"error": f"Server {self.name} is not connected"}

        if self.transport == "stdio":
            result = self._send_request("tools/call", {
                "name": tool_name,
                "arguments": arguments or {},
            })
            if result and "result" in result:
                content = result["result"].get("content", [])
                # Extract text content
                texts = []
                for item in content:
                    if item.get("type") == "text":
                        texts.append(item["text"])
                return {"result": "\n".join(texts) if texts else str(content)}
            error = result.get("error", {}).get("message", "Unknown error") if result else "No response"
            return {"error": error}

        return {"error": "Tool calling not yet supported for SSE transport"}

    def disconnect(self):
        """Disconnect from the server."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        self.status = "disconnected"
        self.tools = []
        self.resources = []


class MCPManager:
    """Manages multiple MCP server connections."""

    def __init__(self):
        self.servers = {}
        self._config_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "data", "mcp_config.json"
        )
        self._load_config()

    def _load_config(self):
        """Load saved MCP server configurations."""
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, "r") as f:
                    config = json.load(f)
                for srv_cfg in config.get("servers", []):
                    server = MCPServer(
                        name=srv_cfg["name"],
                        transport=srv_cfg["transport"],
                        command=srv_cfg.get("command"),
                        url=srv_cfg.get("url"),
                        args=srv_cfg.get("args", []),
                        env=srv_cfg.get("env", {}),
                    )
                    server.id = srv_cfg.get("id", server.id)
                    self.servers[server.id] = server
        except Exception:
            pass

    def _save_config(self):
        """Save MCP server configurations."""
        os.makedirs(os.path.dirname(self._config_file), exist_ok=True)
        config = {
            "servers": [
                {
                    "id": s.id,
                    "name": s.name,
                    "transport": s.transport,
                    "command": s.command,
                    "url": s.url,
                    "args": s.args,
                    "env": s.env,
                }
                for s in self.servers.values()
            ]
        }
        with open(self._config_file, "w") as f:
            json.dump(config, f, indent=2)

    def add_server(self, name, transport, command=None, url=None, args=None, env=None):
        """Add a new MCP server."""
        server = MCPServer(
            name=name,
            transport=transport,
            command=command,
            url=url,
            args=args,
            env=env,
        )
        self.servers[server.id] = server
        self._save_config()
        return server

    def remove_server(self, server_id):
        """Remove an MCP server."""
        server = self.servers.get(server_id)
        if server:
            server.disconnect()
            del self.servers[server_id]
            self._save_config()
            return True
        return False

    def connect_server(self, server_id):
        """Connect to a specific server."""
        server = self.servers.get(server_id)
        if server:
            return server.connect()
        return False

    def disconnect_server(self, server_id):
        """Disconnect from a specific server."""
        server = self.servers.get(server_id)
        if server:
            server.disconnect()
            return True
        return False

    def get_all_tools(self):
        """Get tools from all connected servers."""
        tools = []
        for server in self.servers.values():
            if server.status == "connected":
                for tool in server.tools:
                    tools.append({
                        **tool,
                        "server_id": server.id,
                        "server_name": server.name,
                    })
        return tools

    def call_tool(self, server_id, tool_name, arguments=None):
        """Call a tool on a specific server."""
        server = self.servers.get(server_id)
        if not server:
            return {"error": f"Server not found: {server_id}"}
        return server.call_tool(tool_name, arguments)

    def list_servers(self):
        """List all servers with their status."""
        return [s.to_dict() for s in self.servers.values()]

    def shutdown(self):
        """Disconnect all servers."""
        for server in self.servers.values():
            server.disconnect()
