"""
Vajra AI — AI-Driven Security Expert Platform
Three specialized models: Blue (defense), Red (offense), Hunter (bug bounty)
Main Flask application
"""

import os
import json
import uuid
import time
from datetime import datetime
from flask import Flask, request, jsonify, render_template, Response, stream_with_context
from flask_cors import CORS

from ai_engine import VajraAI
from conversation_store import ConversationStore
from mcp_client import MCPManager
from security_tools import TOOLS as SECURITY_TOOLS, run_tool as run_security_tool

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

# Initialize AI engine, conversation store, and MCP manager
ai_engine = VajraAI()
conversation_store = ConversationStore()
mcp_manager = MCPManager()
ai_engine.mcp_manager = mcp_manager


@app.route("/")
def index():
    """Serve the main chat interface."""
    return render_template("index.html")


@app.route("/api/conversations", methods=["GET"])
def list_conversations():
    """List all conversations."""
    conversations = conversation_store.list_conversations()
    return jsonify({"conversations": conversations})


@app.route("/api/conversations", methods=["POST"])
def create_conversation():
    """Create a new conversation."""
    data = request.json or {}
    title = data.get("title", "New Conversation")
    conversation = conversation_store.create_conversation(title)
    return jsonify(conversation), 201


@app.route("/api/conversations/<conversation_id>", methods=["GET"])
def get_conversation(conversation_id):
    """Get a specific conversation with messages."""
    conversation = conversation_store.get_conversation(conversation_id)
    if not conversation:
        return jsonify({"error": "Conversation not found"}), 404
    return jsonify(conversation)


@app.route("/api/conversations/<conversation_id>", methods=["DELETE"])
def delete_conversation(conversation_id):
    """Delete a conversation."""
    success = conversation_store.delete_conversation(conversation_id)
    if not success:
        return jsonify({"error": "Conversation not found"}), 404
    return jsonify({"message": "Conversation deleted"})


@app.route("/api/conversations/<conversation_id>/title", methods=["PUT"])
def update_conversation_title(conversation_id):
    """Update conversation title."""
    data = request.json or {}
    title = data.get("title", "")
    if not title:
        return jsonify({"error": "Title is required"}), 400
    success = conversation_store.update_title(conversation_id, title)
    if not success:
        return jsonify({"error": "Conversation not found"}), 404
    return jsonify({"message": "Title updated"})


@app.route("/api/chat", methods=["POST"])
def chat():
    """Send a message and get AI response."""
    data = request.json or {}
    message = data.get("message", "").strip()
    conversation_id = data.get("conversation_id")

    if not message:
        return jsonify({"error": "Message is required"}), 400

    # Create conversation if needed
    if not conversation_id:
        conv = conversation_store.create_conversation("New Conversation")
        conversation_id = conv["id"]

    # Store user message
    conversation_store.add_message(conversation_id, "user", message)

    # Get conversation history for context
    conversation = conversation_store.get_conversation(conversation_id)
    history = conversation.get("messages", []) if conversation else []

    # Generate AI response
    ai_response = ai_engine.generate_response(message, history)

    # Store AI response
    conversation_store.add_message(conversation_id, "assistant", ai_response)

    # Auto-generate title from first message
    if conversation and len(history) <= 1:
        auto_title = ai_engine.generate_title(message)
        conversation_store.update_title(conversation_id, auto_title)

    return jsonify({
        "conversation_id": conversation_id,
        "response": ai_response,
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/chat/stream", methods=["POST"])
def chat_stream():
    """Send a message and get streamed AI response."""
    data = request.json or {}
    message = data.get("message", "").strip()
    conversation_id = data.get("conversation_id")

    if not message:
        return jsonify({"error": "Message is required"}), 400

    # Create conversation if needed
    if not conversation_id:
        conv = conversation_store.create_conversation("New Conversation")
        conversation_id = conv["id"]

    # Store user message
    conversation_store.add_message(conversation_id, "user", message)

    # Get conversation history
    conversation = conversation_store.get_conversation(conversation_id)
    history = conversation.get("messages", []) if conversation else []

    def generate():
        full_response = ""
        # Send conversation_id first
        yield f"data: {json.dumps({'type': 'meta', 'conversation_id': conversation_id})}\n\n"

        for chunk in ai_engine.stream_response(message, history):
            full_response += chunk
            yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"

        # Store complete response
        conversation_store.add_message(conversation_id, "assistant", full_response)

        # Auto-generate title
        if conversation and len(history) <= 1:
            auto_title = ai_engine.generate_title(message)
            conversation_store.update_title(conversation_id, auto_title)
            yield f"data: {json.dumps({'type': 'title', 'title': auto_title})}\n\n"

        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/api/models", methods=["GET"])
def list_models():
    """List available AI models."""
    models = ai_engine.get_available_models()
    return jsonify({"models": models, "active": ai_engine.get_active_model()})


@app.route("/api/models/active", methods=["PUT"])
def set_active_model():
    """Set the active model."""
    data = request.json or {}
    model_id = data.get("model_id", "")
    ai_engine.set_active_model(model_id)
    return jsonify({"active": model_id})


# ── Claude API Settings ───────────────────────────────────────────────

@app.route("/api/settings/claude", methods=["GET"])
def get_claude_settings():
    """Get Claude API settings (masked key)."""
    return jsonify({
        "api_key_set": bool(ai_engine._claude_api_key),
        "api_key_masked": ai_engine.get_claude_api_key(),
    })


@app.route("/api/settings/claude", methods=["POST"])
def set_claude_settings():
    """Set the Claude API key."""
    data = request.json or {}
    api_key = data.get("api_key", "").strip()
    if not api_key:
        return jsonify({"error": "API key is required"}), 400
    ai_engine.set_claude_api_key(api_key)
    return jsonify({"message": "API key saved", "api_key_masked": ai_engine.get_claude_api_key()})


@app.route("/api/settings/claude", methods=["DELETE"])
def clear_claude_settings():
    """Clear the Claude API key."""
    ai_engine.set_claude_api_key(None)
    ai_engine._claude_client = None
    return jsonify({"message": "API key cleared"})


@app.route("/api/settings/claude/test", methods=["POST"])
def test_claude_connection():
    """Test the Claude API connection."""
    result = ai_engine.test_claude_connection()
    return jsonify(result)


# ── MCP Server Management ─────────────────────────────────────────────

@app.route("/api/mcp/servers", methods=["GET"])
def list_mcp_servers():
    """List all MCP servers."""
    return jsonify({"servers": mcp_manager.list_servers()})


@app.route("/api/mcp/servers", methods=["POST"])
def add_mcp_server():
    """Add a new MCP server."""
    data = request.json or {}
    name = data.get("name", "").strip()
    transport = data.get("transport", "stdio")
    command = data.get("command", "").strip()
    url = data.get("url", "").strip()
    args = data.get("args", [])
    env = data.get("env", {})

    if not name:
        return jsonify({"error": "Server name is required"}), 400
    if transport == "stdio" and not command:
        return jsonify({"error": "Command is required for stdio transport"}), 400
    if transport == "sse" and not url:
        return jsonify({"error": "URL is required for SSE transport"}), 400

    # Parse args/env if they are strings
    if isinstance(args, str):
        try:
            args = json.loads(args) if args else []
        except json.JSONDecodeError:
            args = []
    if isinstance(env, str):
        try:
            env = json.loads(env) if env else {}
        except json.JSONDecodeError:
            env = {}

    server = mcp_manager.add_server(
        name=name, transport=transport, command=command,
        url=url, args=args, env=env,
    )
    return jsonify(server.to_dict()), 201


@app.route("/api/mcp/servers/<server_id>", methods=["DELETE"])
def remove_mcp_server(server_id):
    """Remove an MCP server."""
    success = mcp_manager.remove_server(server_id)
    if not success:
        return jsonify({"error": "Server not found"}), 404
    return jsonify({"message": "Server removed"})


@app.route("/api/mcp/servers/<server_id>/connect", methods=["POST"])
def connect_mcp_server(server_id):
    """Connect to an MCP server."""
    success = mcp_manager.connect_server(server_id)
    server = mcp_manager.servers.get(server_id)
    if server:
        return jsonify(server.to_dict())
    return jsonify({"error": "Server not found"}), 404


@app.route("/api/mcp/servers/<server_id>/disconnect", methods=["POST"])
def disconnect_mcp_server(server_id):
    """Disconnect from an MCP server."""
    success = mcp_manager.disconnect_server(server_id)
    if not success:
        return jsonify({"error": "Server not found"}), 404
    server = mcp_manager.servers.get(server_id)
    return jsonify(server.to_dict() if server else {"message": "Disconnected"})


@app.route("/api/mcp/tools", methods=["GET"])
def list_mcp_tools():
    """List all available MCP tools from connected servers."""
    tools = mcp_manager.get_all_tools()
    return jsonify({"tools": tools})


# ── Security Tools ─────────────────────────────────────────────────────

@app.route("/api/tools", methods=["GET"])
def list_security_tools():
    """List all available security tools."""
    return jsonify({"tools": SECURITY_TOOLS})


@app.route("/api/tools/run", methods=["POST"])
def execute_security_tool():
    """Execute a security tool and return results."""
    data = request.json or {}
    tool_id = data.get("tool_id", "")
    params = data.get("params", {})

    if not tool_id or tool_id not in SECURITY_TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_id}"}), 400

    # Validate required params
    tool_meta = SECURITY_TOOLS[tool_id]
    for param in tool_meta["params"]:
        if param.get("required") and not params.get(param["name"]):
            return jsonify({"error": f"Parameter '{param['label']}' is required"}), 400

    try:
        result = run_security_tool(tool_id, params)
        return jsonify({"tool_id": tool_id, "result": result})
    except Exception as e:
        return jsonify({"tool_id": tool_id, "result": {"status": "error", "error": str(e)}}), 500


@app.route("/api/tools/run/stream", methods=["POST"])
def execute_security_tool_stream():
    """Execute a security tool with SSE streaming progress."""
    data = request.json or {}
    tool_id = data.get("tool_id", "")
    params = data.get("params", {})

    if not tool_id or tool_id not in SECURITY_TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_id}"}), 400

    tool_meta = SECURITY_TOOLS[tool_id]
    for param in tool_meta["params"]:
        if param.get("required") and not params.get(param["name"]):
            return jsonify({"error": f"Parameter '{param['label']}' is required"}), 400

    def generate():
        yield f"data: {json.dumps({'type': 'start', 'tool': tool_meta['name']})}\n\n"
        try:
            result = run_security_tool(tool_id, params)
            yield f"data: {json.dumps({'type': 'result', 'data': result})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    print("\n🚀 Vajra AI is running at http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
