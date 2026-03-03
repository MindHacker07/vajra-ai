"""
Vajra AI — MCP Server for Security Connectors
Exposes all enabled connectors as MCP-compatible tools so the AI engine
can discover and invoke them through the standard Model Context Protocol.
This runs as a local MCP server (stdio transport).
"""

import sys
import json
import os

# Add parent directory to path so we can import connector_manager
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from connector_manager import ConnectorManager


def main():
    """Run the MCP server over stdio (JSON-RPC 2.0)."""
    manager = ConnectorManager()

    def send(obj):
        """Write a JSON-RPC message to stdout."""
        raw = json.dumps(obj)
        sys.stdout.write(f"Content-Length: {len(raw)}\r\n\r\n{raw}")
        sys.stdout.flush()

    def read_message():
        """Read a JSON-RPC message from stdin (Content-Length framing)."""
        headers = {}
        while True:
            line = sys.stdin.readline()
            if not line:
                return None
            line = line.strip()
            if line == "":
                break
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip()] = val.strip()
        length = int(headers.get("Content-Length", 0))
        if length == 0:
            return None
        body = sys.stdin.read(length)
        return json.loads(body)

    def build_tools_list():
        """Convert enabled connector actions to MCP tool definitions."""
        tools = []
        for action_info in manager.get_all_actions():
            # Build JSON Schema from connector action params
            properties = {}
            required = []
            for p in action_info.get("params", []):
                prop = {"type": "string", "description": p.get("label", p["name"])}
                if p.get("placeholder"):
                    prop["description"] += f" (e.g. {p['placeholder']})"
                if p.get("options"):
                    prop["enum"] = p["options"]
                properties[p["name"]] = prop
                if p.get("required"):
                    required.append(p["name"])

            tool = {
                "name": f"{action_info['connector_id']}__{action_info['action']}",
                "description": f"[{action_info['connector_name']}] {action_info.get('description', action_info.get('name', ''))}",
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            }
            tools.append(tool)
        return tools

    def handle_request(msg):
        method = msg.get("method", "")
        req_id = msg.get("id")
        params = msg.get("params", {})

        if method == "initialize":
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "vajra-connectors", "version": "1.0.0"},
                },
            })
        elif method == "notifications/initialized":
            pass  # notification, no response needed
        elif method == "tools/list":
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": build_tools_list()},
            })
        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            # tool_name format: connector_id__action
            parts = tool_name.split("__", 1)
            if len(parts) != 2:
                send({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Invalid tool name: {tool_name}"}],
                        "isError": True,
                    },
                })
                return
            connector_id, action = parts
            result = manager.execute(connector_id, action, arguments)
            text = json.dumps(result, indent=2, default=str)
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": False},
            })
        else:
            if req_id is not None:
                send({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                })

    # Main loop
    while True:
        try:
            msg = read_message()
            if msg is None:
                break
            handle_request(msg)
        except Exception as e:
            sys.stderr.write(f"MCP Server error: {e}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    main()
