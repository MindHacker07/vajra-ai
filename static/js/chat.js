/**
 * Vajra AI — Chat Interface JavaScript
 * Handles messaging, streaming, conversation management, and UI interactions.
 */

// ── State ─────────────────────────────────────────────────────────────
let currentConversationId = null;
let isStreaming = false;
let conversations = [];
let mcpServers = [];
let securityTools = {};
let currentToolId = null;
let connectors = [];

// ── DOM Elements ──────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const elements = {
    sidebar: $("#sidebar"),
    menuBtn: $("#menuBtn"),
    newChatBtn: $("#newChatBtn"),
    searchInput: $("#searchInput"),
    conversationList: $("#conversationList"),
    chatTitle: $("#chatTitle"),
    deleteConvBtn: $("#deleteConvBtn"),
    messagesContainer: $("#messagesContainer"),
    welcomeScreen: $("#welcomeScreen"),
    messages: $("#messages"),
    messageInput: $("#messageInput"),
    sendBtn: $("#sendBtn"),
    modelSelect: $("#modelSelect"),
    // Settings
    settingsBtn: $("#settingsBtn"),
    settingsModal: $("#settingsModal"),
    settingsClose: $("#settingsClose"),
    claudeApiKey: $("#claudeApiKey"),
    toggleApiKeyVis: $("#toggleApiKeyVis"),
    claudeStatus: $("#claudeStatus"),
    testClaudeBtn: $("#testClaudeBtn"),
    // MCP
    mcpServerList: $("#mcpServerList"),
    mcpTransport: $("#mcpTransport"),
    mcpCommandField: $("#mcpCommandField"),
    mcpUrlField: $("#mcpUrlField"),
    addMcpBtn: $("#addMcpBtn"),
    // Security Tools
    toolsToggleBtn: $("#toolsToggleBtn"),
    toolsPanel: $("#toolsPanel"),
    toolsPanelClose: $("#toolsPanelClose"),
    toolsPanelOverlay: $("#toolsPanelOverlay"),
    toolsTabs: $("#toolsTabs"),
    toolsGrid: $("#toolsGrid"),
    toolExecPanel: $("#toolExecPanel"),
    toolExecHeader: $("#toolExecHeader"),
    toolExecForm: $("#toolExecForm"),
    runToolBtn: $("#runToolBtn"),
    toolOutput: $("#toolOutput"),
    toolOutputContent: $("#toolOutputContent"),
    toolBackBtn: $("#toolBackBtn"),
    toolCopyBtn: $("#toolCopyBtn"),
};

// ── Initialize ────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    initializeApp();
});

async function initializeApp() {
    setupEventListeners();
    await loadConversations();
    await loadClaudeSettings();
    await loadMcpServers();
    await loadSecurityTools();
    await loadConnectors();
    configureMarked();
    elements.messageInput.focus();
}

function configureMarked() {
    if (typeof marked !== "undefined") {
        marked.setOptions({
            breaks: true,
            gfm: true,
            highlight: function (code, lang) {
                if (typeof hljs !== "undefined" && lang && hljs.getLanguage(lang)) {
                    try {
                        return hljs.highlight(code, { language: lang }).value;
                    } catch (_) {}
                }
                return code;
            },
        });
    }
}

// ── Event Listeners ───────────────────────────────────────────────────
function setupEventListeners() {
    // Sidebar toggle
    elements.menuBtn.addEventListener("click", toggleSidebar);

    // New chat
    elements.newChatBtn.addEventListener("click", startNewChat);

    // Search conversations
    elements.searchInput.addEventListener("input", filterConversations);

    // Send message
    elements.sendBtn.addEventListener("click", sendMessage);

    // Delete conversation
    elements.deleteConvBtn.addEventListener("click", deleteCurrentConversation);

    // Textarea auto-resize & keyboard
    elements.messageInput.addEventListener("input", handleInputChange);
    elements.messageInput.addEventListener("keydown", handleInputKeydown);

    // Model selector
    elements.modelSelect.addEventListener("change", handleModelChange);

    // Quick actions
    $$(".quick-action").forEach((btn) => {
        btn.addEventListener("click", () => {
            const prompt = btn.dataset.prompt;
            elements.messageInput.value = prompt;
            handleInputChange();
            sendMessage();
        });
    });

    // Settings modal
    elements.settingsBtn.addEventListener("click", openSettings);
    elements.settingsClose.addEventListener("click", closeSettings);
    elements.settingsModal.addEventListener("click", (e) => {
        if (e.target === elements.settingsModal) closeSettings();
    });

    // Claude API
    elements.testClaudeBtn.addEventListener("click", testClaudeConnection);
    elements.toggleApiKeyVis.addEventListener("click", toggleApiKeyVisibility);
    elements.claudeApiKey.addEventListener("change", saveClaudeApiKey);

    // MCP
    elements.mcpTransport.addEventListener("change", toggleMcpFields);
    elements.addMcpBtn.addEventListener("click", addMcpServer);

    // Security Tools
    elements.toolsToggleBtn.addEventListener("click", toggleToolsPanel);
    elements.toolsPanelClose.addEventListener("click", closeToolsPanel);
    elements.toolsPanelOverlay.addEventListener("click", closeToolsPanel);
    elements.toolBackBtn.addEventListener("click", showToolsGrid);
    elements.runToolBtn.addEventListener("click", executeCurrentTool);
    elements.toolCopyBtn.addEventListener("click", copyToolOutput);

    // Tool category tabs
    elements.toolsTabs.addEventListener("click", (e) => {
        const tab = e.target.closest(".tools-tab");
        if (!tab) return;
        $$(".tools-tab").forEach(t => t.classList.remove("active"));
        tab.classList.add("active");
        renderToolsGrid(tab.dataset.category);
    });

    // Security Connectors
    const connectorConfigBack = document.getElementById("connectorConfigBack");
    if (connectorConfigBack) connectorConfigBack.addEventListener("click", closeConnectorConfig);
    const saveConnectorConfigBtn = document.getElementById("saveConnectorConfig");
    if (saveConnectorConfigBtn) saveConnectorConfigBtn.addEventListener("click", saveConnectorConfig);

    // Close sidebar on mobile when clicking outside
    elements.messagesContainer.addEventListener("click", () => {
        if (window.innerWidth <= 768 && !elements.sidebar.classList.contains("collapsed")) {
            elements.sidebar.classList.add("collapsed");
        }
    });
}

// ── Sidebar ───────────────────────────────────────────────────────────
function toggleSidebar() {
    elements.sidebar.classList.toggle("collapsed");
}

// ── Conversations ─────────────────────────────────────────────────────
async function loadConversations() {
    try {
        const res = await fetch("/api/conversations");
        const data = await res.json();
        conversations = data.conversations || [];
        renderConversationList();
    } catch (err) {
        console.error("Failed to load conversations:", err);
    }
}

function renderConversationList(filter = "") {
    const filtered = filter
        ? conversations.filter((c) => c.title.toLowerCase().includes(filter.toLowerCase()))
        : conversations;

    elements.conversationList.innerHTML = filtered
        .map(
            (conv) => `
        <div class="conv-item ${conv.id === currentConversationId ? "active" : ""}"
             data-id="${conv.id}" onclick="selectConversation('${conv.id}')">
            <div class="conv-item-icon">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                    <path d="M21,15a2,2,0,0,1-2,2H7l-4,4V5A2,2,0,0,1,5,3H19a2,2,0,0,1,2,2Z"></path>
                </svg>
            </div>
            <div class="conv-item-text">
                <div class="conv-item-title">${escapeHtml(conv.title)}</div>
                <div class="conv-item-preview">${escapeHtml(conv.preview || "")}</div>
            </div>
            <button class="conv-item-delete" onclick="event.stopPropagation(); deleteConversation('${conv.id}')" title="Delete">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
            </button>
        </div>
    `
        )
        .join("");
}

function filterConversations() {
    renderConversationList(elements.searchInput.value);
}

async function selectConversation(id) {
    currentConversationId = id;

    // Update active state in sidebar
    $$(".conv-item").forEach((el) => el.classList.remove("active"));
    const activeEl = $(`.conv-item[data-id="${id}"]`);
    if (activeEl) activeEl.classList.add("active");

    // Load conversation messages
    try {
        const res = await fetch(`/api/conversations/${id}`);
        const conv = await res.json();

        elements.chatTitle.textContent = conv.title || "Conversation";
        elements.deleteConvBtn.style.display = "flex";

        // Show messages area, hide welcome
        elements.welcomeScreen.classList.add("hidden");
        elements.messages.innerHTML = "";

        // Render existing messages
        (conv.messages || []).forEach((msg) => {
            appendMessage(msg.role, msg.content, false);
        });

        scrollToBottom();
    } catch (err) {
        console.error("Failed to load conversation:", err);
    }

    // On mobile, close sidebar after selection
    if (window.innerWidth <= 768) {
        elements.sidebar.classList.add("collapsed");
    }
}

async function startNewChat() {
    currentConversationId = null;
    elements.chatTitle.textContent = "New Conversation";
    elements.deleteConvBtn.style.display = "none";
    elements.messages.innerHTML = "";
    elements.welcomeScreen.classList.remove("hidden");
    elements.messageInput.value = "";
    elements.messageInput.focus();
    handleInputChange();

    // Deselect in sidebar
    $$(".conv-item").forEach((el) => el.classList.remove("active"));
}

async function deleteConversation(id) {
    try {
        await fetch(`/api/conversations/${id}`, { method: "DELETE" });
        if (id === currentConversationId) {
            startNewChat();
        }
        await loadConversations();
    } catch (err) {
        console.error("Failed to delete conversation:", err);
    }
}

async function deleteCurrentConversation() {
    if (currentConversationId) {
        await deleteConversation(currentConversationId);
    }
}

// ── Messaging ─────────────────────────────────────────────────────────
async function sendMessage() {
    const message = elements.messageInput.value.trim();
    if (!message || isStreaming) return;

    // Hide welcome, show messages
    elements.welcomeScreen.classList.add("hidden");

    // Clear input
    elements.messageInput.value = "";
    handleInputChange();

    // Append user message
    appendMessage("user", message);
    scrollToBottom();

    // Show typing indicator
    const typingEl = showTypingIndicator();

    // Stream response
    isStreaming = true;
    elements.sendBtn.disabled = true;

    try {
        const response = await fetch("/api/chat/stream", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                message: message,
                conversation_id: currentConversationId,
            }),
        });

        // Remove typing indicator
        typingEl.remove();

        // Create assistant message
        const assistantMsg = appendMessage("assistant", "", true);
        const contentEl = assistantMsg.querySelector(".message-content");

        // Read stream
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let fullContent = "";
        let buffer = "";

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });

            // Process complete SSE messages
            const lines = buffer.split("\n");
            buffer = lines.pop(); // Keep incomplete line in buffer

            for (const line of lines) {
                if (line.startsWith("data: ")) {
                    try {
                        const data = JSON.parse(line.slice(6));

                        if (data.type === "meta") {
                            currentConversationId = data.conversation_id;
                        } else if (data.type === "chunk") {
                            fullContent += data.content;
                            contentEl.innerHTML = renderMarkdown(fullContent);
                            highlightCode(contentEl);
                            addCopyButtons(contentEl);
                            scrollToBottom();
                        } else if (data.type === "title") {
                            elements.chatTitle.textContent = data.title;
                            await loadConversations();
                            // Highlight the active conversation
                            const activeEl = $(`.conv-item[data-id="${currentConversationId}"]`);
                            if (activeEl) activeEl.classList.add("active");
                        } else if (data.type === "done") {
                            // Streaming complete
                        }
                    } catch (e) {
                        // Ignore malformed JSON
                    }
                }
            }
        }

        // Final render with full content
        contentEl.innerHTML = renderMarkdown(fullContent);
        highlightCode(contentEl);
        addCopyButtons(contentEl);

        // Reload conversations to update sidebar
        await loadConversations();
        const activeEl = $(`.conv-item[data-id="${currentConversationId}"]`);
        if (activeEl) activeEl.classList.add("active");
        elements.deleteConvBtn.style.display = "flex";
    } catch (err) {
        console.error("Stream error:", err);
        typingEl.remove();
        appendMessage("assistant", "I'm sorry, something went wrong. Please try again.");
    }

    isStreaming = false;
    elements.sendBtn.disabled = !elements.messageInput.value.trim();
    elements.messageInput.focus();
}

// ── UI Helpers ────────────────────────────────────────────────────────
function appendMessage(role, content, isStreaming = false) {
    const messageEl = document.createElement("div");
    messageEl.className = `message ${role}`;

    const avatar = role === "user" ? "Y" : "V";
    const sender = role === "user" ? "You" : "Vajra";

    const renderedContent = isStreaming ? "" : renderMarkdown(content);

    messageEl.innerHTML = `
        <div class="message-avatar">${avatar}</div>
        <div class="message-body">
            <div class="message-sender">${sender}</div>
            <div class="message-content">${renderedContent}</div>
        </div>
    `;

    elements.messages.appendChild(messageEl);

    if (!isStreaming) {
        const contentEl = messageEl.querySelector(".message-content");
        highlightCode(contentEl);
        addCopyButtons(contentEl);
    }

    scrollToBottom();
    return messageEl;
}

function showTypingIndicator() {
    const typingEl = document.createElement("div");
    typingEl.className = "message assistant";
    typingEl.innerHTML = `
        <div class="message-avatar">V</div>
        <div class="message-body">
            <div class="message-sender">Vajra</div>
            <div class="typing-indicator">
                <div class="typing-dot"></div>
                <div class="typing-dot"></div>
                <div class="typing-dot"></div>
            </div>
        </div>
    `;
    elements.messages.appendChild(typingEl);
    scrollToBottom();
    return typingEl;
}

function scrollToBottom() {
    requestAnimationFrame(() => {
        elements.messagesContainer.scrollTop = elements.messagesContainer.scrollHeight;
    });
}

function handleInputChange() {
    const textarea = elements.messageInput;
    textarea.style.height = "auto";
    textarea.style.height = Math.min(textarea.scrollHeight, 200) + "px";
    elements.sendBtn.disabled = !textarea.value.trim() || isStreaming;
}

function handleInputKeydown(e) {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
}

// ── Markdown & Code ───────────────────────────────────────────────────
function renderMarkdown(text) {
    if (!text) return "";
    if (typeof marked !== "undefined") {
        try {
            return marked.parse(text);
        } catch (e) {
            return escapeHtml(text).replace(/\n/g, "<br>");
        }
    }
    return escapeHtml(text).replace(/\n/g, "<br>");
}

function highlightCode(container) {
    if (typeof hljs !== "undefined") {
        container.querySelectorAll("pre code").forEach((block) => {
            if (!block.dataset.highlighted) {
                hljs.highlightElement(block);
                block.dataset.highlighted = "true";
            }
        });
    }
}

function addCopyButtons(container) {
    container.querySelectorAll("pre").forEach((pre) => {
        if (pre.querySelector(".code-header")) return; // Already has a header

        const code = pre.querySelector("code");
        if (!code) return;

        // Detect language
        const classList = Array.from(code.classList);
        const langClass = classList.find((c) => c.startsWith("language-") || c.startsWith("hljs"));
        let language = "code";
        if (langClass && langClass.startsWith("language-")) {
            language = langClass.replace("language-", "");
        }

        // Create header
        const header = document.createElement("div");
        header.className = "code-header";
        header.innerHTML = `
            <span>${language}</span>
            <button class="copy-btn" onclick="copyCode(this)">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5,15H4a2,2,0,0,1-2-2V4A2,2,0,0,1,4,2H13a2,2,0,0,1,2,2V5"></path>
                </svg>
                Copy
            </button>
        `;
        pre.insertBefore(header, pre.firstChild);
    });
}

function copyCode(btn) {
    const pre = btn.closest("pre");
    const code = pre.querySelector("code");
    const text = code.textContent;

    navigator.clipboard.writeText(text).then(() => {
        const originalHTML = btn.innerHTML;
        btn.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                <polyline points="20,6 9,17 4,12"></polyline>
            </svg>
            Copied!
        `;
        btn.style.color = "#22c55e";
        setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.style.color = "";
        }, 2000);
    });
}

// ── Model Selection ───────────────────────────────────────────────────

const MODEL_THEMES = {
    "vajra-blue": {
        title: "Blue Team — Defensive Security",
        desc: "I'm Vajra Blue — your SOC, DFIR, threat hunting and hardening specialist. Let's defend your organization.",
        color: "#3b82f6",
        actions: [
            { icon: "🛡️", text: "SOC Setup", prompt: "How do I set up a SOC with SIEM, EDR and threat hunting capabilities?" },
            { icon: "🚨", text: "IR Playbook", prompt: "Create an incident response playbook for ransomware attacks" },
            { icon: "🔒", text: "Hardening", prompt: "Give me a comprehensive Windows Active Directory hardening checklist" },
            { icon: "📊", text: "Threat Hunting", prompt: "How to do hypothesis-driven threat hunting with MITRE ATT&CK?" },
        ],
    },
    "vajra-red": {
        title: "Red Team — Offensive Security",
        desc: "I'm Vajra Red — your VAPT, exploitation and adversary simulation specialist. What's the engagement?",
        color: "#ef4444",
        actions: [
            { icon: "🔍", text: "Recon", prompt: "Run a full Nmap scan on a target with service detection and vulnerability scripts" },
            { icon: "🌐", text: "Web Pentest", prompt: "Guide me through a web application penetration test methodology" },
            { icon: "⬆️", text: "Priv Esc", prompt: "Guide me through Linux privilege escalation techniques" },
            { icon: "🏛️", text: "AD Attacks", prompt: "Explain Active Directory attack methodology with BloodHound and Kerberoasting" },
        ],
    },
    "vajra-hunter": {
        title: "Bug Bounty — Security Research",
        desc: "I'm Vajra Hunter — your bug bounty and vulnerability research specialist. Let's find some bugs!",
        color: "#a855f7",
        actions: [
            { icon: "🎯", text: "Bug Bounty", prompt: "How to get started with bug bounty hunting and find my first vulnerability?" },
            { icon: "🔌", text: "API Hacking", prompt: "How to test APIs for BOLA, mass assignment and broken auth vulnerabilities?" },
            { icon: "📝", text: "Report Writing", prompt: "Show me how to write a high-impact bug bounty report with PoC" },
            { icon: "🔍", text: "Recon Pipeline", prompt: "Build me an automated recon pipeline for subdomain discovery and live host scanning" },
        ],
    },
};

function updateWelcomeForModel(modelId) {
    const theme = MODEL_THEMES[modelId];
    if (!theme) return;

    const welcomeTitle = document.getElementById("welcomeTitle");
    const welcomeDesc = document.getElementById("welcomeDesc");
    const quickActions = document.getElementById("quickActions");

    if (welcomeTitle) welcomeTitle.textContent = theme.title;
    if (welcomeDesc) welcomeDesc.textContent = theme.desc;
    if (quickActions) {
        quickActions.innerHTML = theme.actions.map(a =>
            `<button class="quick-action" data-prompt="${a.prompt}">
                <span class="qa-icon">${a.icon}</span>
                <span class="qa-text">${a.text}</span>
            </button>`
        ).join("");
        // Reattach event listeners
        quickActions.querySelectorAll(".quick-action").forEach(btn => {
            btn.addEventListener("click", () => {
                const prompt = btn.dataset.prompt;
                if (prompt) {
                    elements.messageInput.value = prompt;
                    handleSend();
                }
            });
        });
    }

    // Update CSS variable for model accent
    document.documentElement.style.setProperty("--model-accent", theme.color);
}

async function handleModelChange() {
    const modelId = elements.modelSelect.value;

    // If selecting a Claude model, check if API key is set
    if (modelId.startsWith("claude-")) {
        const res = await fetch("/api/settings/claude");
        const data = await res.json();
        if (!data.api_key_set) {
            // Show settings modal
            openSettings();
            elements.claudeApiKey.focus();
            // Reset to built-in
            elements.modelSelect.value = "vajra-blue";
            showToast("Please set your Claude API key first", "warning");
            return;
        }
    }

    // Update welcome screen theme
    updateWelcomeForModel(modelId);

    await fetch("/api/models/active", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model_id: modelId }),
    });
}

// ── Settings Modal ────────────────────────────────────────────────────
function openSettings() {
    elements.settingsModal.classList.add("active");
    loadClaudeSettings();
    loadMcpServers();
}

function closeSettings() {
    elements.settingsModal.classList.remove("active");
}

// ── Claude API ────────────────────────────────────────────────────────
async function loadClaudeSettings() {
    try {
        const res = await fetch("/api/settings/claude");
        const data = await res.json();
        if (data.api_key_set) {
            elements.claudeApiKey.value = data.api_key_masked;
            updateClaudeStatus("connected", "API key configured");
        } else {
            elements.claudeApiKey.value = "";
            updateClaudeStatus("disconnected", "Not connected");
        }
    } catch (err) {
        console.error("Failed to load Claude settings:", err);
    }
}

async function saveClaudeApiKey() {
    const key = elements.claudeApiKey.value.trim();
    if (!key || key.includes("...")) return; // Skip masked values

    try {
        const res = await fetch("/api/settings/claude", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ api_key: key }),
        });
        const data = await res.json();
        if (data.error) {
            showToast(data.error, "error");
        } else {
            elements.claudeApiKey.value = data.api_key_masked;
            updateClaudeStatus("connected", "API key saved");
            showToast("API key saved", "success");
        }
    } catch (err) {
        showToast("Failed to save API key", "error");
    }
}

async function testClaudeConnection() {
    // Save key first if it looks new
    const key = elements.claudeApiKey.value.trim();
    if (key && !key.includes("...")) {
        await saveClaudeApiKey();
    }

    updateClaudeStatus("connecting", "Testing connection...");
    elements.testClaudeBtn.disabled = true;
    elements.testClaudeBtn.textContent = "Testing...";

    try {
        const res = await fetch("/api/settings/claude/test", { method: "POST" });
        const data = await res.json();
        if (data.success) {
            updateClaudeStatus("connected", "Connected ✓");
            showToast("Claude connection successful!", "success");
        } else {
            updateClaudeStatus("error", data.error || "Connection failed");
            showToast(data.error || "Connection failed", "error");
        }
    } catch (err) {
        updateClaudeStatus("error", "Network error");
        showToast("Network error", "error");
    }

    elements.testClaudeBtn.disabled = false;
    elements.testClaudeBtn.textContent = "Test Connection";
}

function updateClaudeStatus(state, text) {
    const dot = elements.claudeStatus.querySelector(".status-dot");
    const label = elements.claudeStatus.querySelector(".status-text");
    dot.className = "status-dot " + state;
    label.textContent = text;
}

function toggleApiKeyVisibility() {
    const input = elements.claudeApiKey;
    input.type = input.type === "password" ? "text" : "password";
}

// ── MCP Servers ───────────────────────────────────────────────────────
async function loadMcpServers() {
    try {
        const res = await fetch("/api/mcp/servers");
        const data = await res.json();
        mcpServers = data.servers || [];
        renderMcpServerList();
    } catch (err) {
        console.error("Failed to load MCP servers:", err);
    }
}

function renderMcpServerList() {
    if (mcpServers.length === 0) {
        elements.mcpServerList.innerHTML = `<div class="mcp-empty">No MCP servers configured yet.</div>`;
        return;
    }

    elements.mcpServerList.innerHTML = mcpServers
        .map(
            (srv) => `
        <div class="mcp-server-card" data-id="${srv.id}">
            <div class="mcp-server-header">
                <div class="mcp-server-info">
                    <span class="status-dot ${srv.status}"></span>
                    <strong>${escapeHtml(srv.name)}</strong>
                    <span class="mcp-transport-badge">${srv.transport.toUpperCase()}</span>
                </div>
                <div class="mcp-server-actions">
                    ${
                        srv.status === "connected"
                            ? `<button class="btn-sm btn-outline" onclick="disconnectMcpServer('${srv.id}')">Disconnect</button>`
                            : `<button class="btn-sm btn-primary" onclick="connectMcpServer('${srv.id}')">Connect</button>`
                    }
                    <button class="btn-sm btn-danger" onclick="removeMcpServer('${srv.id}')">Remove</button>
                </div>
            </div>
            ${srv.status === "connected" && srv.tools.length > 0 ? `
                <div class="mcp-tools-list">
                    <span class="mcp-tools-label">Tools (${srv.tools.length}):</span>
                    ${srv.tools.map((t) => `<span class="mcp-tool-tag" title="${escapeHtml(t.description || '')}">${escapeHtml(t.name)}</span>`).join("")}
                </div>
            ` : ""}
            ${srv.error ? `<div class="mcp-error">${escapeHtml(srv.error)}</div>` : ""}
        </div>
    `
        )
        .join("");
}

function toggleMcpFields() {
    const transport = elements.mcpTransport.value;
    if (transport === "stdio") {
        elements.mcpCommandField.classList.remove("hidden");
        elements.mcpUrlField.classList.add("hidden");
    } else {
        elements.mcpCommandField.classList.add("hidden");
        elements.mcpUrlField.classList.remove("hidden");
    }
}

async function addMcpServer() {
    const name = $("#mcpServerName").value.trim();
    const transport = elements.mcpTransport.value;
    const command = $("#mcpCommand").value.trim();
    const url = $("#mcpUrl").value.trim();
    const argsStr = $("#mcpArgs").value.trim();
    const envStr = $("#mcpEnv").value.trim();

    if (!name) {
        showToast("Server name is required", "error");
        return;
    }

    let args = [];
    let env = {};
    try { if (argsStr) args = JSON.parse(argsStr); } catch (e) { showToast("Invalid args JSON", "error"); return; }
    try { if (envStr) env = JSON.parse(envStr); } catch (e) { showToast("Invalid env JSON", "error"); return; }

    try {
        const res = await fetch("/api/mcp/servers", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, transport, command, url, args, env }),
        });
        const data = await res.json();
        if (data.error) {
            showToast(data.error, "error");
        } else {
            showToast(`Server "${name}" added`, "success");
            // Clear form
            $("#mcpServerName").value = "";
            $("#mcpCommand").value = "";
            $("#mcpUrl").value = "";
            $("#mcpArgs").value = "";
            $("#mcpEnv").value = "";
            await loadMcpServers();
        }
    } catch (err) {
        showToast("Failed to add server", "error");
    }
}

async function connectMcpServer(serverId) {
    showToast("Connecting...", "info");
    try {
        const res = await fetch(`/api/mcp/servers/${serverId}/connect`, { method: "POST" });
        const data = await res.json();
        if (data.status === "connected") {
            showToast(`Connected to "${data.name}" (${data.tools.length} tools)`, "success");
        } else {
            showToast(data.error || "Connection failed", "error");
        }
        await loadMcpServers();
    } catch (err) {
        showToast("Connection failed", "error");
    }
}

async function disconnectMcpServer(serverId) {
    try {
        await fetch(`/api/mcp/servers/${serverId}/disconnect`, { method: "POST" });
        showToast("Disconnected", "info");
        await loadMcpServers();
    } catch (err) {
        showToast("Failed to disconnect", "error");
    }
}

async function removeMcpServer(serverId) {
    try {
        await fetch(`/api/mcp/servers/${serverId}`, { method: "DELETE" });
        showToast("Server removed", "info");
        await loadMcpServers();
    } catch (err) {
        showToast("Failed to remove server", "error");
    }
}

// ── Security Tools ────────────────────────────────────────────────────
async function loadSecurityTools() {
    try {
        const res = await fetch("/api/tools");
        const data = await res.json();
        securityTools = data.tools || {};
        renderToolsGrid("all");
    } catch (err) {
        console.error("Failed to load security tools:", err);
    }
}

function toggleToolsPanel() {
    const isOpen = elements.toolsPanel.classList.contains("open");
    if (isOpen) {
        closeToolsPanel();
    } else {
        openToolsPanel();
    }
}

function openToolsPanel() {
    elements.toolsPanel.classList.add("open");
    elements.toolsPanelOverlay.classList.remove("hidden");
    elements.toolsToggleBtn.classList.add("active");
}

function closeToolsPanel() {
    elements.toolsPanel.classList.remove("open");
    elements.toolsPanelOverlay.classList.add("hidden");
    elements.toolsToggleBtn.classList.remove("active");
}

function renderToolsGrid(category = "all") {
    const entries = Object.entries(securityTools);
    const filtered = category === "all"
        ? entries
        : entries.filter(([_, tool]) => tool.category === category);

    if (filtered.length === 0) {
        elements.toolsGrid.innerHTML = `<div class="tools-empty">No tools in this category.</div>`;
        return;
    }

    elements.toolsGrid.innerHTML = filtered.map(([id, tool]) => `
        <div class="tool-card" data-tool-id="${id}" onclick="selectTool('${id}')">
            <div class="tool-card-icon">${tool.icon}</div>
            <div class="tool-card-info">
                <div class="tool-card-name">${escapeHtml(tool.name)}</div>
                <div class="tool-card-desc">${escapeHtml(tool.description)}</div>
            </div>
            <div class="tool-card-arrow">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                    <polyline points="9 18 15 12 9 6"></polyline>
                </svg>
            </div>
        </div>
    `).join("");
}

function selectTool(toolId) {
    const tool = securityTools[toolId];
    if (!tool) return;

    currentToolId = toolId;

    // Hide grid, show execution panel
    elements.toolsGrid.classList.add("hidden");
    elements.toolsTabs.classList.add("hidden");
    elements.toolExecPanel.classList.remove("hidden");

    // Build header
    elements.toolExecHeader.innerHTML = `
        <div class="tool-exec-icon">${tool.icon}</div>
        <div>
            <h3>${escapeHtml(tool.name)}</h3>
            <p>${escapeHtml(tool.description)}</p>
        </div>
    `;

    // Build parameter form
    elements.toolExecForm.innerHTML = tool.params.map(param => {
        if (param.type === "select") {
            const options = (param.options || []).map(opt =>
                `<option value="${escapeHtml(opt)}">${escapeHtml(opt)}</option>`
            ).join("");
            return `
                <div class="tool-param">
                    <label for="tool-param-${param.name}">${escapeHtml(param.label)}${param.required ? ' <span class="required">*</span>' : ''}</label>
                    <select id="tool-param-${param.name}" class="tool-param-input" data-param="${param.name}">
                        ${options}
                    </select>
                </div>
            `;
        }
        return `
            <div class="tool-param">
                <label for="tool-param-${param.name}">${escapeHtml(param.label)}${param.required ? ' <span class="required">*</span>' : ''}</label>
                <input type="text" id="tool-param-${param.name}" class="tool-param-input"
                       data-param="${param.name}"
                       placeholder="${escapeHtml(param.placeholder || '')}"
                       value="${escapeHtml(param.default || '')}" />
            </div>
        `;
    }).join("");

    // Reset output
    elements.toolOutput.classList.add("hidden");
    elements.toolOutputContent.textContent = "";
    elements.runToolBtn.disabled = false;
    elements.runToolBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <polygon points="5 3 19 12 5 21 5 3"></polygon>
        </svg>
        Execute
    `;
}

function showToolsGrid() {
    elements.toolExecPanel.classList.add("hidden");
    elements.toolsGrid.classList.remove("hidden");
    elements.toolsTabs.classList.remove("hidden");
    currentToolId = null;
}

async function executeCurrentTool() {
    if (!currentToolId) return;

    // Collect parameters
    const paramInputs = elements.toolExecForm.querySelectorAll(".tool-param-input");
    const params = {};
    paramInputs.forEach(input => {
        params[input.dataset.param] = input.value.trim();
    });

    // Disable button, show loading
    elements.runToolBtn.disabled = true;
    elements.runToolBtn.innerHTML = `
        <div class="tool-spinner"></div>
        Running...
    `;

    // Show output area
    elements.toolOutput.classList.remove("hidden");
    elements.toolOutputContent.textContent = "⏳ Executing tool, please wait...\n";

    try {
        const res = await fetch("/api/tools/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ tool_id: currentToolId, params }),
        });

        const data = await res.json();

        if (data.error) {
            elements.toolOutputContent.textContent = `❌ Error: ${data.error}`;
            showToast(data.error, "error");
        } else {
            const output = formatToolOutput(currentToolId, data.result);
            elements.toolOutputContent.innerHTML = output;
            showToast("Tool executed successfully", "success");
        }
    } catch (err) {
        elements.toolOutputContent.textContent = `❌ Error: ${err.message}`;
        showToast("Tool execution failed", "error");
    }

    elements.runToolBtn.disabled = false;
    elements.runToolBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <polygon points="5 3 19 12 5 21 5 3"></polygon>
        </svg>
        Execute
    `;
}

function formatToolOutput(toolId, result) {
    if (result.error && result.status === "error") {
        return `<span class="tool-out-error">❌ Error: ${escapeHtml(result.error)}</span>`;
    }

    let out = "";

    switch (toolId) {
        case "port_scanner":
            out += `<span class="tool-out-header">🔌 Port Scan Results — ${escapeHtml(result.target)}</span>\n`;
            out += `<span class="tool-out-dim">IP: ${escapeHtml(result.ip || "N/A")} | Scanned: ${result.total_scanned} ports | Time: ${result.scan_time}s</span>\n\n`;
            if (result.open_ports.length === 0) {
                out += `<span class="tool-out-warn">No open ports found.</span>\n`;
            } else {
                out += `<span class="tool-out-label">PORT        STATE    SERVICE       BANNER</span>\n`;
                out += `<span class="tool-out-dim">────────────────────────────────────────────────</span>\n`;
                result.open_ports.forEach(p => {
                    const port = String(p.port).padEnd(12);
                    const state = "open".padEnd(9);
                    const service = (p.service || "unknown").padEnd(14);
                    const banner = p.banner ? p.banner.substring(0, 60) : "";
                    out += `<span class="tool-out-success">${port}${state}</span>${escapeHtml(service)}${escapeHtml(banner)}\n`;
                });
                out += `\n<span class="tool-out-success">✓ ${result.open_ports.length} open port(s) found</span>`;
            }
            break;

        case "network_scanner":
            out += `<span class="tool-out-header">🌐 Network Discovery — ${escapeHtml(result.network)}</span>\n`;
            out += `<span class="tool-out-dim">Scan time: ${result.scan_time}s</span>\n\n`;
            if (result.hosts.length === 0) {
                out += `<span class="tool-out-warn">No live hosts found.</span>\n`;
            } else {
                out += `<span class="tool-out-label">IP ADDRESS          HOSTNAME</span>\n`;
                out += `<span class="tool-out-dim">────────────────────────────────────────</span>\n`;
                result.hosts.forEach(h => {
                    const ip = h.ip.padEnd(20);
                    out += `<span class="tool-out-success">●</span> ${escapeHtml(ip)}${escapeHtml(h.hostname || "-")}\n`;
                });
                out += `\n<span class="tool-out-success">✓ ${result.hosts.length} live host(s) discovered</span>`;
            }
            break;

        case "subdomain_enum":
            out += `<span class="tool-out-header">🔍 Subdomain Enumeration — ${escapeHtml(result.domain)}</span>\n`;
            out += `<span class="tool-out-dim">Scan time: ${result.scan_time}s</span>\n\n`;
            if (result.subdomains.length === 0) {
                out += `<span class="tool-out-warn">No subdomains found.</span>\n`;
            } else {
                out += `<span class="tool-out-label">SUBDOMAIN                              IP ADDRESS</span>\n`;
                out += `<span class="tool-out-dim">──────────────────────────────────────────────────────</span>\n`;
                result.subdomains.forEach(s => {
                    const sub = s.subdomain.padEnd(40);
                    out += `${escapeHtml(sub)}<span class="tool-out-dim">${escapeHtml(s.ip)}</span>\n`;
                });
                out += `\n<span class="tool-out-success">✓ ${result.subdomains.length} subdomain(s) found</span>`;
            }
            break;

        case "header_analyzer":
            out += `<span class="tool-out-header">🛡️ Security Header Analysis — ${escapeHtml(result.url)}</span>\n`;
            out += `<span class="tool-out-dim">HTTP Status: ${result.http_status || "N/A"}</span>\n\n`;

            const gradeColor = result.score >= 75 ? "tool-out-success" : result.score >= 50 ? "tool-out-warn" : "tool-out-error";
            out += `<span class="${gradeColor}">Security Score: ${result.score}/100 (Grade: ${result.grade})</span>\n\n`;

            if (result.missing_headers.length > 0) {
                out += `<span class="tool-out-error">Missing Security Headers:</span>\n`;
                result.missing_headers.forEach(h => {
                    const sev = h.severity === "high" ? "🔴" : h.severity === "medium" ? "🟡" : "🟢";
                    out += `  ${sev} ${escapeHtml(h.header)}\n     <span class="tool-out-dim">${escapeHtml(h.description)}</span>\n`;
                });
            }

            if (result.info_disclosure.length > 0) {
                out += `\n<span class="tool-out-warn">Information Disclosure:</span>\n`;
                result.info_disclosure.forEach(d => {
                    out += `  ⚠️  ${escapeHtml(d.header)}: ${escapeHtml(d.value)}\n     <span class="tool-out-dim">${escapeHtml(d.risk)}</span>\n`;
                });
            }

            if (result.server_info && Object.keys(result.server_info).length > 0) {
                out += `\n<span class="tool-out-label">Server Info:</span>\n`;
                Object.entries(result.server_info).forEach(([k, v]) => {
                    out += `  ${escapeHtml(k)}: ${escapeHtml(v)}\n`;
                });
            }
            break;

        case "tech_detector":
            out += `<span class="tool-out-header">🔬 Technology Detection — ${escapeHtml(result.url)}</span>\n\n`;
            if (result.technologies.length === 0) {
                out += `<span class="tool-out-warn">No technologies detected.</span>\n`;
            } else {
                out += `<span class="tool-out-label">TECHNOLOGY          CATEGORY              VERSION</span>\n`;
                out += `<span class="tool-out-dim">──────────────────────────────────────────────────────</span>\n`;
                result.technologies.forEach(t => {
                    const name = t.name.padEnd(20);
                    const cat = (t.category || "").padEnd(22);
                    out += `<span class="tool-out-success">●</span> ${escapeHtml(name)}${escapeHtml(cat)}${escapeHtml(t.version || "-")}\n`;
                });
                out += `\n<span class="tool-out-success">✓ ${result.technologies.length} technolog(ies) detected</span>`;
            }
            break;

        case "dir_bruteforce":
            out += `<span class="tool-out-header">📂 Directory Bruteforce — ${escapeHtml(result.url)}</span>\n`;
            out += `<span class="tool-out-dim">Checked: ${result.total_checked} paths | Time: ${result.scan_time}s</span>\n\n`;
            if (result.found.length === 0) {
                out += `<span class="tool-out-warn">No directories/files found.</span>\n`;
            } else {
                out += `<span class="tool-out-label">PATH                               STATUS    SIZE</span>\n`;
                out += `<span class="tool-out-dim">──────────────────────────────────────────────────────</span>\n`;
                result.found.forEach(f => {
                    const path = f.path.padEnd(35);
                    const status = String(f.status).padEnd(10);
                    const statusClass = f.status === 200 ? "tool-out-success" : f.status === 403 ? "tool-out-warn" : "tool-out-dim";
                    out += `${escapeHtml(path)}<span class="${statusClass}">${escapeHtml(status)}</span>${f.size || 0}B\n`;
                });
                out += `\n<span class="tool-out-success">✓ ${result.found.length} path(s) discovered</span>`;
            }
            break;

        case "hash_cracker":
            out += `<span class="tool-out-header">🔓 Hash Cracker Results</span>\n\n`;
            out += `<span class="tool-out-label">Hash:</span> ${escapeHtml(result.hash)}\n`;
            out += `<span class="tool-out-label">Type:</span> ${escapeHtml(result.hash_type.join(", "))}\n`;
            out += `<span class="tool-out-label">Attempts:</span> ${result.attempts}\n`;
            out += `<span class="tool-out-label">Time:</span> ${result.crack_time}s\n\n`;
            if (result.cracked) {
                out += `<span class="tool-out-success">✓ CRACKED!</span>\n`;
                out += `<span class="tool-out-success">Plaintext: ${escapeHtml(result.plaintext)}</span>\n`;
            } else {
                out += `<span class="tool-out-warn">✗ Not cracked with current wordlist.</span>\n`;
                if (result.error) {
                    out += `<span class="tool-out-dim">${escapeHtml(result.error)}</span>\n`;
                }
            }
            break;

        case "reverse_shell":
            if (result.error) {
                out += `<span class="tool-out-error">${escapeHtml(result.error)}</span>`;
            } else {
                out += `<span class="tool-out-header">💣 Reverse Shell Payload — ${escapeHtml(result.type)}</span>\n\n`;
                out += `<span class="tool-out-label">LHOST:</span> ${escapeHtml(result.lhost)}\n`;
                out += `<span class="tool-out-label">LPORT:</span> ${escapeHtml(result.lport)}\n\n`;
                out += `<span class="tool-out-warn">⚡ Payload:</span>\n`;
                out += `<span class="tool-out-code">${escapeHtml(result.payload)}</span>\n\n`;
                out += `<span class="tool-out-warn">🎧 Listener:</span>\n`;
                out += `<span class="tool-out-code">${escapeHtml(result.listener)}</span>\n\n`;
                out += `<span class="tool-out-dim">Base64 Encoded:</span>\n`;
                out += `<span class="tool-out-code">${escapeHtml(result.encoded.base64)}</span>\n`;
            }
            break;

        case "dns_recon":
            out += `<span class="tool-out-header">📡 DNS Recon — ${escapeHtml(result.domain)}</span>\n\n`;
            const records = result.records || {};
            if (records.A && records.A.length > 0) {
                out += `<span class="tool-out-label">A Record:</span> ${escapeHtml(records.A.join(", "))}\n`;
            }
            if (records.ALL_IPS && records.ALL_IPS.length > 0) {
                out += `<span class="tool-out-label">All IPs:</span> ${escapeHtml(records.ALL_IPS.join(", "))}\n`;
            }
            if (records.PTR && records.PTR.length > 0) {
                out += `<span class="tool-out-label">Reverse DNS:</span> ${escapeHtml(records.PTR.join(", "))}\n`;
            }
            if (records.MX_GUESS && records.MX_GUESS.length > 0) {
                out += `\n<span class="tool-out-label">Mail Servers (guessed):</span>\n`;
                records.MX_GUESS.forEach(mx => {
                    out += `  <span class="tool-out-success">●</span> ${escapeHtml(mx.host)} → ${escapeHtml(mx.ip)}\n`;
                });
            }
            if (records.NS_GUESS && records.NS_GUESS.length > 0) {
                out += `\n<span class="tool-out-label">Name Servers (guessed):</span>\n`;
                records.NS_GUESS.forEach(ns => {
                    out += `  <span class="tool-out-success">●</span> ${escapeHtml(ns.host)} → ${escapeHtml(ns.ip)}\n`;
                });
            }
            break;

        case "encoder":
            out += `<span class="tool-out-header">🔄 ${escapeHtml(result.operation)} (${escapeHtml(result.encoding)})</span>\n\n`;
            out += `<span class="tool-out-label">Input:</span>\n${escapeHtml(result.input)}\n\n`;
            out += `<span class="tool-out-label">Output:</span>\n<span class="tool-out-code">${escapeHtml(String(result.output))}</span>\n`;
            break;

        default:
            out = JSON.stringify(result, null, 2);
    }

    return out;
}

function copyToolOutput() {
    const text = elements.toolOutputContent.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast("Output copied to clipboard", "success");
    });
}

// ── Security Connectors ───────────────────────────────────────────────
async function loadConnectors() {
    try {
        const res = await fetch("/api/connectors");
        const data = await res.json();
        connectors = data.connectors || [];
        renderConnectorList();
    } catch (err) {
        console.error("Failed to load connectors:", err);
    }
}

function renderConnectorList() {
    const container = document.getElementById("connectorList");
    if (!container) return;
    if (connectors.length === 0) {
        container.innerHTML = `<div class="mcp-empty">No connectors available.</div>`;
        return;
    }

    container.innerHTML = connectors.map(c => `
        <div class="connector-card" data-id="${c.connector_id}">
            <div class="connector-card-header">
                <div class="connector-card-info">
                    <span class="connector-icon">${c.icon}</span>
                    <div>
                        <strong>${escapeHtml(c.name)}</strong>
                        <span class="connector-category-badge">${escapeHtml(c.category)}</span>
                    </div>
                </div>
                <label class="toggle-switch">
                    <input type="checkbox" ${c.enabled ? "checked" : ""}
                           onchange="toggleConnector('${c.connector_id}', this.checked)" />
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <p class="connector-card-desc">${escapeHtml(c.description)}</p>
            <div class="connector-card-actions">
                <button class="btn-sm btn-outline" onclick="checkConnectorHealth('${c.connector_id}')">
                    Health Check
                </button>
                <button class="btn-sm btn-outline" onclick="openConnectorConfig('${c.connector_id}')">
                    Configure
                </button>
                ${c.website ? `<a class="btn-sm btn-outline" href="${escapeHtml(c.website)}" target="_blank" rel="noopener">Docs</a>` : ""}
            </div>
            <div class="connector-health-result hidden" id="health-${c.connector_id}"></div>
        </div>
    `).join("");
}

async function toggleConnector(connectorId, enabled) {
    try {
        const res = await fetch(`/api/connectors/${connectorId}/toggle`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled }),
        });
        const data = await res.json();
        if (data.error) {
            showToast(data.error, "error");
        } else {
            showToast(`${data.name} ${enabled ? "enabled" : "disabled"}`, "success");
            await loadConnectors();
        }
    } catch (err) {
        showToast("Failed to toggle connector", "error");
    }
}

async function checkConnectorHealth(connectorId) {
    const el = document.getElementById(`health-${connectorId}`);
    if (el) {
        el.classList.remove("hidden");
        el.innerHTML = `<span class="tool-spinner"></span> Checking...`;
    }
    try {
        const res = await fetch(`/api/connectors/${connectorId}/health`);
        const data = await res.json();
        if (el) {
            const health = data.health || data;
            const ok = health.ok;
            el.innerHTML = `<span class="${ok ? "tool-out-success" : "tool-out-error"}">${ok ? "✓" : "✗"} ${escapeHtml(health.message || JSON.stringify(health))}</span>`;
        }
    } catch (err) {
        if (el) el.innerHTML = `<span class="tool-out-error">✗ Health check failed</span>`;
    }
}

function openConnectorConfig(connectorId) {
    const connector = connectors.find(c => c.connector_id === connectorId);
    if (!connector) return;

    const panel = document.getElementById("connectorConfigPanel");
    const title = document.getElementById("connectorConfigTitle");
    const form = document.getElementById("connectorConfigForm");
    const sections = document.querySelectorAll("#settingsModal .settings-section");

    // Hide settings sections, show config panel
    sections.forEach(s => s.classList.add("hidden"));
    panel.classList.remove("hidden");
    panel.dataset.connectorId = connectorId;
    title.textContent = `${connector.icon} ${connector.name} Configuration`;

    // Build config form
    const config = connector.config || {};
    form.innerHTML = Object.entries(config).map(([key, val]) => {
        const isSecret = /key|secret|password|token/i.test(key);
        return `
            <div class="settings-field">
                <label for="cc-${key}">${escapeHtml(key)}</label>
                <input type="${isSecret ? "password" : "text"}" id="cc-${key}"
                       data-config-key="${key}"
                       value="${isSecret ? "" : escapeHtml(String(val))}"
                       placeholder="${isSecret ? "(hidden)" : ""}" />
            </div>
        `;
    }).join("") || `<p class="settings-desc">No configurable options for this connector.</p>`;
}

function closeConnectorConfig() {
    const panel = document.getElementById("connectorConfigPanel");
    const sections = document.querySelectorAll("#settingsModal .settings-section");
    panel.classList.add("hidden");
    sections.forEach(s => s.classList.remove("hidden"));
}

async function saveConnectorConfig() {
    const panel = document.getElementById("connectorConfigPanel");
    const connectorId = panel.dataset.connectorId;
    const inputs = panel.querySelectorAll("[data-config-key]");
    const config = {};
    inputs.forEach(input => {
        const key = input.dataset.configKey;
        const val = input.value.trim();
        if (val) config[key] = val;  // Only send non-empty values
    });

    try {
        const res = await fetch(`/api/connectors/${connectorId}/config`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ config }),
        });
        const data = await res.json();
        if (data.error) {
            showToast(data.error, "error");
        } else {
            showToast("Configuration saved", "success");
            await loadConnectors();
            closeConnectorConfig();
        }
    } catch (err) {
        showToast("Failed to save configuration", "error");
    }
}

// ── Toast Notifications ───────────────────────────────────────────────
function showToast(message, type = "info") {
    const existing = $(".toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add("show"));
    setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ── Utilities ─────────────────────────────────────────────────────────
function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}
