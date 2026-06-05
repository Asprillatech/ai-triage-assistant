"""
AI Triage Assistant
A rule-based IT support and cybersecurity triage tool built with Streamlit.
No API key required — works immediately out of the box.
"""

import streamlit as st
from triage_engine import analyze_issue
from samples import SAMPLE_ISSUES

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Triage Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Import fonts */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600&display=swap');

/* Global */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Dark terminal header */
.main-header {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
}
.main-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, #58a6ff, #3fb950, #f85149);
}
.main-header h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.8rem;
    font-weight: 600;
    color: #e6edf3;
    margin: 0 0 0.3rem 0;
}
.main-header p {
    color: #8b949e;
    margin: 0;
    font-size: 0.95rem;
}

/* Severity badges */
.badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.05em;
}
.badge-critical { background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }
.badge-high     { background: #3d2a0a; color: #d29922; border: 1px solid #d29922; }
.badge-medium   { background: #1a2d1a; color: #3fb950; border: 1px solid #3fb950; }
.badge-low      { background: #1a2035; color: #58a6ff; border: 1px solid #58a6ff; }
.badge-unknown  { background: #2a2a2a; color: #8b949e; border: 1px solid #8b949e; }

/* Result card */
.result-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1rem;
}
.result-card h3 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #58a6ff;
    margin: 0 0 0.6rem 0;
}
.result-card p, .result-card li {
    color: #c9d1d9;
    font-size: 0.92rem;
    line-height: 1.6;
    margin: 0;
}
.result-card ul, .result-card ol {
    margin: 0;
    padding-left: 1.4rem;
}
.result-card ol li {
    margin-bottom: 0.3rem;
}

/* Ticket note box */
.ticket-box {
    background: #0d1117;
    border: 1px solid #3fb950;
    border-left: 4px solid #3fb950;
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    color: #c9d1d9;
    white-space: pre-wrap;
    line-height: 1.7;
}

/* Escalation box */
.escalation-box {
    border-radius: 8px;
    padding: 1rem 1.5rem;
    margin-bottom: 1rem;
}
.escalation-yes {
    background: #3d1a1a;
    border: 1px solid #f85149;
    color: #f85149;
}
.escalation-no {
    background: #1a2d1a;
    border: 1px solid #3fb950;
    color: #3fb950;
}
.escalation-box p { margin: 0; font-weight: 500; }

/* Sidebar styling */
[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #21262d;
}
[data-testid="stSidebar"] .stButton button {
    width: 100%;
    text-align: left;
    background: #161b22;
    border: 1px solid #30363d;
    color: #c9d1d9;
    border-radius: 6px;
    font-size: 0.82rem;
    padding: 0.5rem 0.8rem;
    margin-bottom: 0.3rem;
    transition: all 0.15s ease;
}
[data-testid="stSidebar"] .stButton button:hover {
    border-color: #58a6ff;
    color: #58a6ff;
    background: #161b22;
}

/* Analyze button */
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #1f6feb, #388bfd);
    border: none;
    color: white;
    font-weight: 600;
    border-radius: 8px;
    padding: 0.6rem 2rem;
    font-size: 0.95rem;
    transition: opacity 0.2s;
}
.stButton > button[kind="primary"]:hover {
    opacity: 0.88;
}

/* Textarea */
.stTextArea textarea {
    background: #0d1117 !important;
    border: 1px solid #30363d !important;
    color: #c9d1d9 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.88rem !important;
    border-radius: 8px !important;
}
.stTextArea textarea:focus {
    border-color: #58a6ff !important;
    box-shadow: 0 0 0 3px rgba(88,166,255,0.1) !important;
}

/* Divider */
hr { border-color: #21262d; }

/* Info text */
.info-note {
    background: #1c2128;
    border: 1px solid #30363d;
    border-left: 3px solid #58a6ff;
    border-radius: 6px;
    padding: 0.6rem 1rem;
    color: #8b949e;
    font-size: 0.82rem;
    margin-top: 0.5rem;
}
</style>
""", unsafe_allow_html=True)


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🛡️ AI Triage Assistant</h1>
    <p>IT Support &amp; Cybersecurity alert triage · Rule-based engine · No API key required</p>
</div>
""", unsafe_allow_html=True)


# ── Sidebar — sample issues ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 📋 Sample Issues")
    st.markdown("Click a sample to load it into the input box.")
    st.markdown("---")

    for label, text in SAMPLE_ISSUES.items():
        if st.button(label, key=f"sample_{label}"):
            st.session_state["issue_input"] = text

    st.markdown("---")
    st.markdown("""
    <div style='color:#8b949e; font-size:0.8rem; line-height:1.6;'>
    <strong style='color:#c9d1d9;'>About</strong><br>
    Rule-based triage engine that classifies IT &amp; security issues by keyword matching and generates structured responses.<br><br>
    Built as a portfolio project for an AI Fellow application.
    </div>
    """, unsafe_allow_html=True)


# ── Main input ────────────────────────────────────────────────────────────────
col1, col2 = st.columns([3, 1])
with col1:
    st.markdown("#### Paste your issue or alert below")

issue_text = st.text_area(
    label="Issue / Alert Input",
    label_visibility="collapsed",
    placeholder="e.g.  User reports they cannot log into their laptop after a password reset. They also noticed unfamiliar login attempts in their email account...",
    height=160,
    key="issue_input",
)

col_btn, col_clear, col_spacer = st.columns([1, 1, 5])
with col_btn:
    analyze_clicked = st.button("🔍 Analyze", type="primary", use_container_width=True)
with col_clear:
    if st.button("✕ Clear", use_container_width=True):
        st.session_state["issue_input"] = ""
        st.rerun()

st.markdown("""
<div class="info-note">
⚙️ &nbsp;This app uses a <strong>rule-based engine</strong> — no API key needed.
For LLM-powered analysis, see the roadmap in <code>README.md</code>.
</div>
""", unsafe_allow_html=True)


# ── Analysis output ───────────────────────────────────────────────────────────
if analyze_clicked:
    if not issue_text.strip():
        st.warning("⚠️  Please enter an issue or alert before clicking Analyze.")
    else:
        with st.spinner("Analyzing issue…"):
            result = analyze_issue(issue_text)

        st.markdown("---")
        st.markdown("## 📊 Triage Report")

        # Row 1 — summary + category + severity
        r1c1, r1c2, r1c3 = st.columns([3, 1.5, 1.2])

        with r1c1:
            st.markdown(f"""
            <div class="result-card">
                <h3>📝 Issue Summary</h3>
                <p>{result['summary']}</p>
            </div>
            """, unsafe_allow_html=True)

        with r1c2:
            st.markdown(f"""
            <div class="result-card">
                <h3>🗂️ Category</h3>
                <p>{result['category']}</p>
            </div>
            """, unsafe_allow_html=True)

        with r1c3:
            sev = result["severity"].lower()
            badge_class = f"badge-{sev}" if sev in ("critical","high","medium","low") else "badge-unknown"
            st.markdown(f"""
            <div class="result-card">
                <h3>⚡ Severity</h3>
                <span class="badge {badge_class}">{result['severity']}</span>
            </div>
            """, unsafe_allow_html=True)

        # Row 2 — causes + questions
        r2c1, r2c2 = st.columns(2)

        with r2c1:
            causes_html = "".join(f"<li>{c}</li>" for c in result["likely_causes"])
            st.markdown(f"""
            <div class="result-card">
                <h3>🔎 Likely Causes</h3>
                <ul>{causes_html}</ul>
            </div>
            """, unsafe_allow_html=True)

        with r2c2:
            questions_html = "".join(f"<li>{q}</li>" for q in result["clarifying_questions"])
            st.markdown(f"""
            <div class="result-card">
                <h3>❓ Clarifying Questions</h3>
                <ul>{questions_html}</ul>
            </div>
            """, unsafe_allow_html=True)

        # Troubleshooting steps
        steps_html = "".join(f"<li>{s}</li>" for s in result["troubleshooting_steps"])
        st.markdown(f"""
        <div class="result-card">
            <h3>🛠️ Step-by-Step Troubleshooting</h3>
            <ol>{steps_html}</ol>
        </div>
        """, unsafe_allow_html=True)

        # Escalation
        esc = result["escalation"]
        esc_class = "escalation-yes" if esc["recommended"] else "escalation-no"
        esc_icon  = "🚨" if esc["recommended"] else "✅"
        esc_label = "Escalation RECOMMENDED" if esc["recommended"] else "Escalation NOT required"
        st.markdown(f"""
        <div class="escalation-box {esc_class}">
            <p>{esc_icon} &nbsp;<strong>{esc_label}</strong> — {esc['reason']}</p>
        </div>
        """, unsafe_allow_html=True)

        # Ticket note
        st.markdown("""
        <div class="result-card">
            <h3>🎫 Clean Ticket Note</h3>
        </div>
        """, unsafe_allow_html=True)
        st.markdown(f'<div class="ticket-box">{result["ticket_note"]}</div>', unsafe_allow_html=True)

        # Copy helper
        st.text_area(
            "Copy ticket note 👇",
            value=result["ticket_note"],
            height=180,
            key="ticket_copy",
            label_visibility="collapsed",
        )
