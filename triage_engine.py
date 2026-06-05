"""
triage_engine.py
Rule-based triage logic for the AI Triage Assistant.
Classifies issues by keyword matching and fills structured response templates.
No API key or external service required.
"""

from __future__ import annotations
import re
from datetime import datetime


# ── Category definitions ──────────────────────────────────────────────────────
# Each entry: (category_label, severity, keywords)
CATEGORY_RULES: list[tuple[str, str, list[str]]] = [
    # ── Cybersecurity (highest priority, checked first) ──
    ("Ransomware / Malware",        "CRITICAL", ["ransom", "ransomware", "encrypt", "your files", "malware", "virus", "trojan", "worm", "infected", "infection"]),
    ("Phishing / Social Engineering","HIGH",    ["phish", "phishing", "suspicious email", "suspicious link", "clicked a link", "spoofed", "impersonat", "fake invoice", "pretending to be"]),
    ("Unauthorized Access",         "CRITICAL", ["unauthorized", "brute force", "credential stuffing", "account takeover", "hacked", "compromised account", "strange login", "unknown login", "unfamiliar login", "login from unknown"]),
    ("Data Breach / Exfiltration",  "CRITICAL", ["data breach", "data leak", "exfiltrat", "sensitive data exposed", "pii exposed", "customer data", "leaked"]),
    ("DDoS / Network Attack",       "HIGH",     ["ddos", "denial of service", "flood", "traffic spike", "network attack", "port scan"]),
    ("Suspicious Process / Endpoint","HIGH",    ["suspicious process", "unknown process", "unexpected process", "unusual activity", "endpoint alert", "edr alert", "siem alert", "security alert"]),
    ("Firewall / IDS Alert",        "MEDIUM",   ["firewall", "ids", "ips", "intrusion", "blocked traffic", "rule triggered", "snort", "suricata"]),
    ("Vulnerability / Patch",       "MEDIUM",   ["vulnerability", "cve-", "patch", "unpatched", "exploit", "security update", "missing update"]),

    # ── Identity & Access ──
    ("Account Lockout",             "MEDIUM",   ["locked out", "account locked", "lockout", "cannot log in", "can't log in", "login fail", "login issue", "password reset", "forgot password", "reset password"]),
    ("MFA / 2FA Issue",             "MEDIUM",   ["mfa", "2fa", "two-factor", "authenticator", "otp", "verification code", "auth app"]),
    ("Permissions / Access Request","LOW",      ["permission", "access denied", "forbidden", "no access", "need access", "request access", "role", "privilege"]),

    # ── Network & Connectivity ──
    ("VPN Issue",                   "MEDIUM",   ["vpn", "remote access", "tunnel", "cisco anyconnect", "globalprotect", "wireguard", "openvpn"]),
    ("Network / Internet Outage",   "HIGH",     ["internet down", "network down", "no internet", "network outage", "cannot connect", "connectivity", "ping fail", "latency", "packet loss"]),
    ("Wi-Fi Issue",                 "MEDIUM",   ["wifi", "wi-fi", "wireless", "ssid", "cannot connect to wifi", "drops connection"]),
    ("DNS Issue",                   "MEDIUM",   ["dns", "domain resolution", "cannot resolve", "nslookup", "name resolution"]),

    # ── Hardware ──
    ("Hardware Failure",            "HIGH",     ["blue screen", "bsod", "kernel panic", "hardware fail", "disk fail", "hard drive", "ssd fail", "ram fail", "memory error", "not booting", "won't boot", "dead", "no power"]),
    ("Printer / Peripheral",        "LOW",      ["printer", "printing", "scanner", "usb device", "peripheral", "keyboard", "mouse", "monitor", "display"]),
    ("Performance / Slowness",      "MEDIUM",   ["slow", "sluggish", "freeze", "freezing", "hang", "unresponsive", "high cpu", "high memory", "100% cpu", "overheating", "fan noise"]),

    # ── Software & Applications ──
    ("Software Crash / Error",      "MEDIUM",   ["crash", "crashing", "error message", "application error", "not responding", "exception", "stack trace", "runtime error"]),
    ("Email Issue",                 "MEDIUM",   ["email", "outlook", "gmail", "mail", "cannot send", "cannot receive", "email bouncing", "spam", "mailbox full"]),
    ("Cloud / SaaS Issue",          "MEDIUM",   ["cloud", "saas", "microsoft 365", "office 365", "google workspace", "salesforce", "slack", "teams", "zoom", "sharepoint", "onedrive"]),
    ("OS / System Update",          "LOW",      ["windows update", "macos update", "os update", "system update", "upgrade", "update fail"]),
    ("Software Installation",       "LOW",      ["install", "installation", "uninstall", "setup", "deployment", "software request"]),

    # ── General fallback ──
    ("General IT Support",          "LOW",      []),
]


# ── Per-category response templates ──────────────────────────────────────────
TEMPLATES: dict[str, dict] = {
    "Ransomware / Malware": {
        "summary_prefix": "Possible ransomware or malware infection detected on user system.",
        "causes": [
            "User opened a malicious email attachment or clicked a phishing link",
            "Drive-by download from a compromised website",
            "Infected USB drive or external media",
            "Unpatched software exploited by an attack",
        ],
        "questions": [
            "When did you first notice the issue? What were you doing at the time?",
            "Did you open any email attachments or click any links recently?",
            "Is the issue limited to one device, or are other machines affected?",
            "Are files showing unusual extensions (e.g. .locked, .encrypted)?",
            "Is the system still accessible, or is it completely locked?",
        ],
        "steps": [
            "IMMEDIATELY isolate the affected device from the network (disconnect Wi-Fi and Ethernet).",
            "Do NOT turn off the machine — preserve evidence for forensics.",
            "Document visible ransom notes, error messages, or changed file extensions.",
            "Alert the security team and management — this is a P1 incident.",
            "Identify the ransomware variant if possible (nomoreransom.org).",
            "Check backups: determine last clean backup and whether it is also affected.",
            "Do NOT pay the ransom without consulting legal and security leadership.",
            "Initiate incident response plan and preserve logs from SIEM/EDR.",
        ],
        "escalate": (True, "Ransomware is a P1 security incident — escalate to Security Team and Management immediately."),
    },

    "Phishing / Social Engineering": {
        "summary_prefix": "User reports a suspected phishing or social engineering attempt.",
        "causes": [
            "Targeted spear-phishing email mimicking a trusted sender",
            "Mass phishing campaign reaching corporate inboxes",
            "Business Email Compromise (BEC) targeting finance/HR",
            "SMS phishing (smishing) or voice phishing (vishing)",
        ],
        "questions": [
            "Did you click any links or download any attachments in the email?",
            "Did you enter any credentials or personal information on any website?",
            "What email address/domain did the message appear to come from?",
            "Has anyone else in the org reported a similar message?",
            "Is the email still in your inbox or was it deleted?",
        ],
        "steps": [
            "Ask the user NOT to interact further with the email (no clicking, no downloading).",
            "Have the user forward the email (as an attachment) to the security team.",
            "Check if the user clicked any links — review browser history and proxy logs.",
            "If credentials were entered, force an immediate password reset and invalidate sessions.",
            "Enable MFA on all affected accounts if not already active.",
            "Block the sending domain/IP in the email gateway.",
            "Run an EDR scan on the affected endpoint.",
            "Notify all staff if the campaign appears widespread.",
        ],
        "escalate": (True, "Potential credential compromise — escalate to Security Team for investigation."),
    },

    "Unauthorized Access": {
        "summary_prefix": "Suspected unauthorized access to a user account or system detected.",
        "causes": [
            "Stolen or guessed credentials (brute force, credential stuffing)",
            "Password reuse from a previously breached service",
            "Phishing attack resulting in credential theft",
            "Session token hijacking",
            "Insider threat or shared credentials",
        ],
        "questions": [
            "What service or system shows the suspicious login?",
            "What location or IP address is associated with the unknown login?",
            "Has the user shared their credentials with anyone?",
            "Is MFA enabled on this account?",
            "Have any settings, data, or emails been modified by the unauthorized party?",
        ],
        "steps": [
            "Immediately lock or disable the affected account to prevent further access.",
            "Force a password reset via a secure out-of-band channel.",
            "Revoke all active sessions and OAuth tokens for the account.",
            "Enable or re-enroll MFA on the account.",
            "Review audit logs to determine the extent of access (what was viewed/modified).",
            "Check for unauthorized email forwarding rules, admin changes, or data downloads.",
            "Preserve log evidence for forensic review.",
            "Notify the user and relevant stakeholders.",
        ],
        "escalate": (True, "Account compromise is a security incident — escalate to Security Team immediately."),
    },

    "Account Lockout": {
        "summary_prefix": "User is locked out of their account and unable to authenticate.",
        "causes": [
            "Multiple failed login attempts triggered the lockout policy",
            "Recent password reset not properly propagated (e.g. cached credentials)",
            "Credentials entered incorrectly (Caps Lock, old password)",
            "Malicious brute-force attempt locking the account",
            "Syncing issue between identity provider and downstream apps",
        ],
        "questions": [
            "Which account or system is the user locked out of?",
            "Did the user recently change their password?",
            "Is Caps Lock or Num Lock active on the keyboard?",
            "Has the user tried logging in from a different device or browser?",
            "Are multiple accounts affected, or just this one?",
        ],
        "steps": [
            "Verify the user's identity through a secondary channel (phone, employee ID).",
            "Unlock the account via the identity provider admin console (AD, Azure AD, Okta, etc.).",
            "Have the user reset their password to a new, strong, unique value.",
            "Clear any cached/saved credentials from browsers and OS credential managers.",
            "Confirm the new credentials work on all required systems.",
            "If the lockout recurs automatically, check for a device or app sending stale credentials.",
            "Review lockout logs for signs of a brute-force attack — if detected, escalate.",
        ],
        "escalate": (False, "Standard account lockout — handle with Tier 1 support unless brute-force is suspected."),
    },

    "VPN Issue": {
        "summary_prefix": "User is experiencing problems connecting to or using the corporate VPN.",
        "causes": [
            "Incorrect VPN credentials or expired certificate",
            "VPN client software out of date",
            "Local firewall or antivirus blocking the VPN connection",
            "ISP-level port blocking (common on hotel/public Wi-Fi)",
            "VPN server-side issue or maintenance window",
        ],
        "questions": [
            "Which VPN client are you using (Cisco AnyConnect, GlobalProtect, etc.)?",
            "What exact error message are you receiving?",
            "Did the VPN work previously, or is this a first-time setup?",
            "What network are you connecting from (home, hotel, office)?",
            "Have there been any recent changes to your device or credentials?",
        ],
        "steps": [
            "Confirm the VPN service is operational (check status page or ping the gateway).",
            "Have the user verify they are using the correct server address and credentials.",
            "Ensure the VPN client is on the latest approved version.",
            "Ask the user to temporarily disable local antivirus/firewall and retry.",
            "Try connecting on a different network (mobile hotspot) to rule out ISP blocking.",
            "Re-install the VPN client if the issue persists.",
            "If the problem affects multiple users, escalate to the network team.",
        ],
        "escalate": (False, "Isolated VPN issue — resolve with standard Tier 1/2 steps."),
    },

    "Network / Internet Outage": {
        "summary_prefix": "User or site is reporting loss of network or internet connectivity.",
        "causes": [
            "ISP outage or upstream provider issue",
            "Misconfigured router, switch, or firewall rule",
            "Physical cable damage or hardware failure (switch, router)",
            "DHCP scope exhaustion preventing IP assignment",
            "BGP routing issue affecting traffic paths",
        ],
        "questions": [
            "Is the outage affecting one user, a department, or the whole site?",
            "Can internal resources be reached even if the internet is down?",
            "When did the outage start? Were any changes made before it began?",
            "Are there any error messages on the affected devices?",
            "Has the network hardware (router, switch) been restarted?",
        ],
        "steps": [
            "Check the ISP status page or contact the ISP to rule out an upstream outage.",
            "Test connectivity at multiple layers: ping gateway, ping 8.8.8.8, then DNS resolution.",
            "Inspect switch and router status lights for physical layer issues.",
            "Review recent firewall/router change logs for accidental misconfigurations.",
            "Restart the affected network hardware (follow change management process).",
            "Check DHCP scope utilization — expand if near capacity.",
            "Escalate to the network team if the issue persists beyond 15 minutes.",
        ],
        "escalate": (True, "Site-wide or multi-user outage — escalate to Network Team immediately."),
    },

    "Hardware Failure": {
        "summary_prefix": "User's device is experiencing a hardware failure or critical system crash.",
        "causes": [
            "Failing or failed hard drive / SSD",
            "RAM failure causing blue screen / kernel panic",
            "Overheating due to blocked vents or failed cooling system",
            "Power supply unit (PSU) failure",
            "Corrupted operating system or boot sector",
        ],
        "questions": [
            "What error message or code is displayed (BSOD stop code, kernel panic text)?",
            "Is the machine completely unresponsive or intermittently crashing?",
            "How old is the device? Has it been dropped or physically damaged?",
            "Are there unusual sounds (clicking, grinding) from the machine?",
            "When did this issue start? Were any updates or changes made recently?",
        ],
        "steps": [
            "If the device is still bootable, immediately back up critical user data.",
            "Run built-in diagnostics (e.g. Dell SupportAssist, Apple Diagnostics, Windows Memory Diagnostic).",
            "Check SMART data on the drive using CrystalDiskInfo or similar tool.",
            "Inspect event logs (Windows Event Viewer / macOS Console) for hardware errors.",
            "Boot from a live USB to determine if the issue is hardware vs OS.",
            "If hardware failure is confirmed, arrange a replacement device for the user.",
            "Escalate to hardware team for warranty / depot repair if needed.",
        ],
        "escalate": (True, "Hardware failure may require device replacement — escalate to Tier 2/hardware team."),
    },

    "Software Crash / Error": {
        "summary_prefix": "An application is crashing or producing error messages on the user's device.",
        "causes": [
            "Corrupted application installation or missing dependencies",
            "Incompatible software version after a recent OS or app update",
            "Insufficient system resources (RAM, disk space)",
            "Corrupted user profile or application cache",
            "Bug in the application requiring a vendor patch",
        ],
        "questions": [
            "Which application is crashing, and what version is installed?",
            "What exact error message or error code is displayed?",
            "Did this start after a recent update (OS or application)?",
            "Does the crash happen immediately on launch or during a specific action?",
            "Does the issue affect only this user, or others on the same machine or network?",
        ],
        "steps": [
            "Note the full error message and any error codes for reference.",
            "Restart the application and attempt to reproduce the issue.",
            "Check available disk space and RAM — clear up resources if needed.",
            "Clear the application cache and temporary files.",
            "Uninstall and reinstall the application using a fresh installer.",
            "Check the vendor's support site for known bugs or patches.",
            "If the issue is linked to a recent update, consider rolling back.",
            "Collect crash dump files and escalate to Tier 2 if unresolved.",
        ],
        "escalate": (False, "Software crash — resolve with Tier 1 steps; escalate to Tier 2 if reinstall fails."),
    },

    "Email Issue": {
        "summary_prefix": "User is experiencing issues sending, receiving, or accessing email.",
        "causes": [
            "Mailbox quota exceeded preventing new mail delivery",
            "Incorrect mail server settings (SMTP/IMAP/POP3)",
            "Email client misconfiguration or outdated software",
            "Anti-spam filter incorrectly flagging legitimate mail",
            "Account credential issue blocking access",
        ],
        "questions": [
            "What email client are you using (Outlook, web browser, mobile app)?",
            "What is the exact error message you receive?",
            "Are you unable to send, receive, or both?",
            "Is the issue affecting all recipients or just specific ones?",
            "Did the issue start after a recent password change or update?",
        ],
        "steps": [
            "Check if the issue occurs in both the email client and webmail (OWA/Gmail web) — this isolates client vs server issues.",
            "Verify the user's mailbox quota and clear old mail if over limit.",
            "Check mail server health/status dashboard for known outages.",
            "Test sending/receiving with a simple test email to an internal address.",
            "Re-enter email account credentials in the client.",
            "Check spam/junk folders for missing messages.",
            "Review email client settings (server addresses, ports, SSL).",
            "Escalate to mail admin if server-side issue is suspected.",
        ],
        "escalate": (False, "Email issue — handle with Tier 1; escalate to mail admin if server-side."),
    },

    "Performance / Slowness": {
        "summary_prefix": "User reports their device or application is running slowly or unresponsively.",
        "causes": [
            "Background processes or startup programs consuming excessive resources",
            "Insufficient available RAM or CPU for current workload",
            "Near-full hard drive degrading performance",
            "Malware or rogue process consuming resources",
            "Fragmented disk (HDD) or failing drive",
        ],
        "questions": [
            "Is the slowness system-wide or limited to specific applications?",
            "When did the slowness begin? Was there a recent update or software install?",
            "How much free disk space is available?",
            "Has the machine been restarted recently?",
            "Does Task Manager / Activity Monitor show any process using excessive CPU or memory?",
        ],
        "steps": [
            "Restart the device if it hasn't been rebooted recently.",
            "Open Task Manager (Windows) or Activity Monitor (macOS) and identify high-resource processes.",
            "End any unnecessary background processes.",
            "Check disk space — clear temp files, recycle bin, and old downloads if disk is >90% full.",
            "Run a malware scan to rule out a malicious process.",
            "Review startup programs and disable non-essential ones.",
            "Check for pending OS/driver updates.",
            "If the issue persists, consider a RAM or SSD upgrade for the device.",
        ],
        "escalate": (False, "Performance issue — typically resolved at Tier 1; escalate if malware is suspected."),
    },
}

# Default template for categories without a specific template
DEFAULT_TEMPLATE = {
    "summary_prefix": "User has submitted an IT support request.",
    "causes": [
        "Recent software or configuration change",
        "User error or unfamiliarity with the system",
        "Underlying service or dependency issue",
        "Hardware or network fault",
    ],
    "questions": [
        "When did this issue start?",
        "Have there been any recent changes to your device or software?",
        "Is anyone else experiencing the same issue?",
        "What troubleshooting steps have you already tried?",
        "What is the business impact of this issue?",
    ],
    "steps": [
        "Gather full details from the user: device, OS, application version, and exact error.",
        "Attempt to reproduce the issue in a controlled environment.",
        "Check relevant service/system status pages for known outages.",
        "Review recent changes to the system (updates, patches, config changes).",
        "Apply standard troubleshooting for the reported symptom.",
        "Document all findings and actions taken in the ticket.",
        "Escalate to Tier 2 if the issue is not resolved within SLA.",
    ],
    "escalate": (False, "Standard IT support request — handle per normal SLA guidelines."),
}


# ── Core classifier ────────────────────────────────────────────────────────────
def classify(text: str) -> tuple[str, str]:
    """Return (category, severity) by matching keywords in the issue text."""
    lower = text.lower()
    for category, severity, keywords in CATEGORY_RULES:
        if any(kw in lower for kw in keywords):
            return category, severity
    return "General IT Support", "LOW"


def get_template(category: str) -> dict:
    """Return the best-matching template for the given category."""
    return TEMPLATES.get(category, DEFAULT_TEMPLATE)


def build_summary(text: str, template: dict) -> str:
    """Generate a concise one-sentence summary from the issue text."""
    # Trim the raw input to ~120 chars for the summary note
    snippet = text.strip().replace("\n", " ")
    if len(snippet) > 120:
        snippet = snippet[:117] + "…"
    return f"{template['summary_prefix']} User reported: \"{snippet}\""


def build_ticket_note(
    summary: str,
    category: str,
    severity: str,
    escalate: bool,
    escalate_reason: str,
) -> str:
    """Format a clean ticket note ready to paste into a ticketing system."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    esc_line = "YES — " + escalate_reason if escalate else "No — " + escalate_reason
    return (
        f"[AI TRIAGE — {now}]\n"
        f"Category  : {category}\n"
        f"Severity  : {severity}\n"
        f"Escalate  : {esc_line}\n"
        f"\n"
        f"Summary:\n{summary}\n"
        f"\n"
        f"--- Auto-generated by AI Triage Assistant ---"
    )


# ── Public API ────────────────────────────────────────────────────────────────
def analyze_issue(text: str) -> dict:
    """
    Main entry point.
    Accepts raw issue text, returns a structured triage dict.
    """
    category, severity = classify(text)
    template = get_template(category)
    summary = build_summary(text, template)
    escalate, escalate_reason = template["escalate"]

    ticket_note = build_ticket_note(summary, category, severity, escalate, escalate_reason)

    return {
        "summary": summary,
        "category": category,
        "severity": severity,
        "likely_causes": template["causes"],
        "clarifying_questions": template["questions"],
        "troubleshooting_steps": template["steps"],
        "escalation": {
            "recommended": escalate,
            "reason": escalate_reason,
        },
        "ticket_note": ticket_note,
    }
