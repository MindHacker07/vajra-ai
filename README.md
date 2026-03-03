# Vajra AI — AI-Driven Security Expert

A conversational AI platform with three specialized cybersecurity models, built-in security tools, and optional Claude API integration.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0+-green?logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Models

| Model               | Focus                 | Use Case                                                          |
| ------------------- | --------------------- | ----------------------------------------------------------------- |
| 🛡️ **Vajra Blue**   | Blue Team / Defense   | SOC, SIEM, DFIR, threat hunting, hardening, compliance            |
| ⚔️ **Vajra Red**    | Red Team / Offense    | VAPT, exploitation, AD attacks, adversary simulation              |
| 🎯 **Vajra Hunter** | Bug Bounty / Research | Vulnerability hunting, API security, report writing, CVE research |

## Features

- **Three specialized AI models** — switch between defense, offense, and bug bounty modes
- **Built-in knowledge engine** — deep cybersecurity knowledge base with actionable responses
- **Security tools** — Port scanner, subdomain enum, header analyzer, log analyzer, IOC scanner, config auditor, and more
- **Claude API integration** — optional Anthropic Claude (Sonnet 4 / Opus 4.5) for enhanced responses
- **MCP protocol support** — connect external tool servers via Model Context Protocol
- **Streaming responses** — real-time word-by-word response streaming
- **Conversation persistence** — chat history saved locally as JSON
- **Modern UI** — dark theme, markdown rendering, syntax highlighting, model-aware theming

## Quick Start

```bash
# Clone the repository
git clone https://github.com/MindHacker07/vajra-ai.git
cd vajra-ai

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Open **http://localhost:5000** in your browser.

## Optional: Claude API

To use Claude models, add your Anthropic API key in the Settings panel within the app (gear icon → Claude API Key).

## Project Structure

```
├── app.py                 # Flask application & API routes
├── ai_engine.py           # Core AI engine with 3 model profiles
├── security_tools.py      # Executable security tools (recon + defense)
├── mcp_client.py          # Model Context Protocol client
├── conversation_store.py  # JSON-based conversation persistence
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html         # Main chat UI
├── static/
│   ├── css/style.css      # Styles with model-aware theming
│   └── js/chat.js         # Frontend logic & model switching
└── data/
    └── conversations.json # Local chat history
```

## Security Tools

### Offensive (Red/Hunter)

- Port Scanner — multi-threaded TCP scan with banner grabbing
- Network Discovery — live host detection via TCP ping
- Subdomain Enumerator — DNS brute-force + certificate transparency
- Header Analyzer — HTTP security header scoring
- Technology Detector — web stack fingerprinting
- Directory Bruteforcer — hidden file/directory discovery
- Hash Cracker — MD5/SHA1/SHA256 dictionary attack
- Reverse Shell Generator — multi-language payload generation
- DNS Recon — record enumeration
- Encoder/Decoder — Base64, URL, Hex, HTML, hashing

### Defensive (Blue)

- Log Analyzer — detect brute-force, injection, exfil patterns
- IOC Scanner — extract IPs, domains, hashes, CVEs from text
- Config Auditor — audit SSH/nginx/Apache configurations
- Password Auditor — strength analysis & common password check

## Disclaimer

⚠️ **All offensive security features are intended for authorized testing only.** Always ensure you have written permission before testing any system. Use responsibly and ethically.

## License

MIT License — see [LICENSE](LICENSE) for details.
