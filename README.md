# 🛡️ AI Triage Assistant

AI prototype for IT support and cybersecurity triage built with Python and Streamlit. No API key or paid service required.

---

## What This Project Does

IT and security teams are constantly flooded with support tickets and security alerts. Manually triaging each one is slow, inconsistent, and exhausting.

**AI Triage Assistant** automates the first-pass analysis of any incoming IT support issue or cybersecurity alert. Paste in a raw issue description and instantly get:

- A structured **issue summary**
- Automatic **category** detection (ransomware, phishing, VPN, hardware, etc.)
- A **severity rating** (Critical / High / Medium / Low)
- A list of **likely causes**
- Smart **clarifying questions** for the affected user
- Step-by-step **troubleshooting guidance**
- A clear **escalation recommendation**
- A clean, copy-pasteable **ticket note**

---

## Why I Built It

I built this as a portfolio project to demonstrate:

1. **Applied AI thinking** — designing structured, reliable outputs from unstructured input
2. **Domain knowledge** — IT support and cybersecurity triage workflows
3. **Product instinct** — building something immediately usable without friction (no API key needed)
4. **Python engineering** — clean, modular, readable code a team could extend

My goal was to show how AI-style reasoning can be approximated with rule-based logic as a fast, deployable baseline — and then describe a clear roadmap to upgrade it with real LLMs.

---

## Features

- 🔍 **Instant triage** — no API key, no internet required after install
- 🗂️ **15+ issue categories** — covers ransomware, phishing, account lockouts, VPN, hardware, email, performance, and more
- ⚡ **Severity scoring** — Critical, High, Medium, Low
- 📋 **8 sample issues** in the sidebar for quick demos
- 🎫 **Ready-to-paste ticket notes** with timestamps
- 🎨 **Dark terminal UI** — clean, professional, portfolio-ready

---

## How to Run

### 1. Clone or download the project

```bash
git clone https://github.com/yourusername/ai-triage-assistant.git
cd ai-triage-assistant
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Requires **Python 3.9+** and only one dependency: `streamlit`.

### 3. Launch the app

```bash
streamlit run app.py
```

The app will open automatically at `http://localhost:8501`.

---

## Project Structure

```
ai-triage-assistant/
├── app.py              # Streamlit UI
├── triage_engine.py    # Rule-based classification + response generation
├── samples.py          # Sample issues for the sidebar
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## How It Works

The triage engine (`triage_engine.py`) uses **keyword matching** to classify issues:

1. The user's raw text is lowercased and scanned against a priority-ordered list of category rules.
2. Each category rule contains a keyword list, a default severity, and a pointer to a response template.
3. The matched template fills in: causes, clarifying questions, troubleshooting steps, and escalation guidance.
4. A ticket note is assembled from the classification results and returned to the UI.

This approach is:
- **Deterministic** — same input always gives the same output
- **Fast** — sub-millisecond response, no network calls
- **Transparent** — easy to audit, update, and extend
- **A solid baseline** before adding an LLM

---

## What I Learned

- How to structure a rule-based classification system that mimics the reasoning of an experienced L1 analyst
- How to design Streamlit UIs that feel polished and professional, not like demos
- The importance of graceful degradation — a useful tool *today* that can be upgraded *tomorrow*
- How to think about AI products in tiers: rules → LLM → RAG → autonomous agents

---

## Future Improvements

### 🤖 LLM Integration (Phase 2)
Replace the rule-based engine with a call to the **Anthropic Claude API** (or OpenAI GPT-4). The LLM would:
- Understand nuanced, multi-issue descriptions that keyword matching misses
- Generate richer, context-aware troubleshooting steps
- Handle novel issue types not covered by predefined rules

```python
# Drop-in replacement for analyze_issue()
import anthropic
client = anthropic.Anthropic(api_key="YOUR_KEY")
response = client.messages.create(
    model="claude-opus-4-5",
    system=TRIAGE_SYSTEM_PROMPT,
    messages=[{"role": "user", "content": issue_text}]
)
```

### 📚 RAG — Retrieval-Augmented Generation (Phase 3)
Connect the app to a **knowledge base** of:
- Internal runbooks and SOPs
- Past resolved tickets
- Vendor documentation
- CVE / threat intelligence feeds

Using a vector database (e.g. Pinecone, Chroma), the LLM would ground its responses in your organization's actual procedures.

### 🎫 Ticketing System Integration (Phase 4)
Auto-create tickets in **ServiceNow**, **Jira Service Management**, or **Zendesk** via their REST APIs. The triage output would map directly to ticket fields: priority, category, description, assignee.

### 📊 Analytics Dashboard (Phase 5)
Track triage history, most common issue categories, severity distribution, and escalation rates over time using a lightweight SQLite database + Streamlit charts.

### 🔐 Authentication & Multi-Tenant Support
Add SSO / LDAP login and support multiple teams or clients with isolated triage histories.

---

## License

MIT — free to use, modify, and distribute.
