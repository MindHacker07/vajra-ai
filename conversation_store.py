"""
Vajra AI - Conversation Store
Manages conversation persistence using JSON file storage.
"""

import os
import json
import uuid
from datetime import datetime


DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CONVERSATIONS_FILE = os.path.join(DATA_DIR, "conversations.json")


class ConversationStore:
    """Manages conversation storage and retrieval."""

    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(CONVERSATIONS_FILE):
            self._save_data({"conversations": {}})

    def _load_data(self):
        """Load all conversations from disk."""
        try:
            with open(CONVERSATIONS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"conversations": {}}

    def _save_data(self, data):
        """Save all conversations to disk."""
        with open(CONVERSATIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def create_conversation(self, title="New Conversation"):
        """Create a new conversation."""
        data = self._load_data()
        conv_id = str(uuid.uuid4())[:8]
        conversation = {
            "id": conv_id,
            "title": title,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "messages": [],
        }
        data["conversations"][conv_id] = conversation
        self._save_data(data)
        return conversation

    def get_conversation(self, conversation_id):
        """Get a conversation by ID."""
        data = self._load_data()
        return data["conversations"].get(conversation_id)

    def list_conversations(self):
        """List all conversations (sorted by last updated)."""
        data = self._load_data()
        conversations = list(data["conversations"].values())
        conversations.sort(key=lambda c: c.get("updated_at", ""), reverse=True)
        # Return summaries without full message content for the list view
        return [
            {
                "id": c["id"],
                "title": c["title"],
                "created_at": c["created_at"],
                "updated_at": c["updated_at"],
                "message_count": len(c.get("messages", [])),
                "preview": c["messages"][-1]["content"][:80] + "..."
                if c.get("messages") and len(c["messages"][-1]["content"]) > 80
                else c["messages"][-1]["content"]
                if c.get("messages")
                else "",
            }
            for c in conversations
        ]

    def add_message(self, conversation_id, role, content):
        """Add a message to a conversation."""
        data = self._load_data()
        conv = data["conversations"].get(conversation_id)
        if not conv:
            return None
        message = {
            "id": str(uuid.uuid4())[:8],
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
        }
        conv["messages"].append(message)
        conv["updated_at"] = datetime.now().isoformat()
        self._save_data(data)
        return message

    def delete_conversation(self, conversation_id):
        """Delete a conversation."""
        data = self._load_data()
        if conversation_id in data["conversations"]:
            del data["conversations"][conversation_id]
            self._save_data(data)
            return True
        return False

    def update_title(self, conversation_id, title):
        """Update conversation title."""
        data = self._load_data()
        conv = data["conversations"].get(conversation_id)
        if not conv:
            return False
        conv["title"] = title
        conv["updated_at"] = datetime.now().isoformat()
        self._save_data(data)
        return True
