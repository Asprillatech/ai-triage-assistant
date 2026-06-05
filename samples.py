"""
samples.py
Pre-written sample issues for the sidebar quick-load buttons.
"""

SAMPLE_ISSUES: dict[str, str] = {
    "🔒 Ransomware Alert": (
        "Alert from EDR: Multiple files on WORKSTATION-04 have been renamed with the extension "
        ".locked in the past 5 minutes. A text file named 'READ_ME_TO_RECOVER.txt' appeared on "
        "the Desktop. The user reports they opened an invoice attachment from an unknown email "
        "about 10 minutes ago. Affected drive: C:\\ — approximately 3,000 files renamed so far."
    ),
    "🎣 Phishing Email": (
        "A user in the Finance department received an email appearing to be from the CFO "
        "requesting an urgent wire transfer of $42,000 to a new vendor. The email address is "
        "cfo@company-finance.net (our real domain is company.com). The user almost completed "
        "the transfer. They forwarded the email to IT. No links were clicked."
    ),
    "🔑 Account Lockout": (
        "User jsmith@company.com is locked out of their Windows laptop and Microsoft 365 account "
        "after returning from a 2-week vacation. They say they cannot remember if they changed "
        "their password before leaving. They need urgent access to prepare a client presentation "
        "in 30 minutes."
    ),
    "🌐 VPN Not Connecting": (
        "Remote employee working from home cannot connect to the corporate VPN using Cisco "
        "AnyConnect. The error message says 'Authentication failed. Please try again.' She is "
        "certain she is using the correct credentials. The VPN was working fine last week. "
        "Her home router and internet connection are both working normally."
    ),
    "💻 Laptop Blue Screen": (
        "Sales rep's Dell XPS 15 (Windows 11) is crashing with a BSOD showing stop code "
        "CRITICAL_PROCESS_DIED approximately every 2 hours. The laptop is 3 years old and "
        "has been running slower than usual for the past month. The user hears a faint "
        "clicking noise from inside the machine when it starts up."
    ),
    "📧 Can't Send Emails": (
        "User reports they can receive emails in Outlook but cannot send any. They get the "
        "error: 'The message could not be sent. The server responded: 550 5.7.1 Relaying "
        "denied.' This started this morning. Other team members can send emails normally. "
        "The user recently changed their Microsoft 365 password yesterday afternoon."
    ),
    "🐢 Slow Computer": (
        "An HR manager's computer has become extremely slow over the past week. Opening "
        "applications takes 3-4 minutes, and the machine often freezes for 30-60 seconds "
        "at random. Task Manager shows CPU usage constantly at 95-100%. She hasn't "
        "installed any new software recently. The machine runs Windows 10 and is 4 years old."
    ),
    "🚨 Suspicious Login": (
        "Microsoft 365 security alert: User mpatel@company.com logged in successfully from "
        "an IP address in Romania at 03:14 AM local time. The user is based in Chicago and "
        "was not traveling. The account does not have MFA enabled. No unusual email activity "
        "detected yet, but the login occurred 2 hours ago."
    ),
}
