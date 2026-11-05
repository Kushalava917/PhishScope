"""Reserved-domain, inert fixtures. No executable attachment bytes."""

from email.message import EmailMessage


def sample(
    key, title, sender, subject, body, reply=None, auth="fail", attachment=False
):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "Analyst <analyst@company.example>"
    msg["Subject"] = subject
    msg["Date"] = "Thu, 05 Nov 2026 09:00:00 +0000"
    msg["Message-ID"] = f"<{key}@simulation.example>"
    msg["Received"] = (
        "from mail.simulation.example ([192.0.2.25]) by gateway.company.example; Thu, 05 Nov 2026 09:00:00 +0000"
    )
    msg["Authentication-Results"] = (
        f"gateway.company.example; spf={auth}; dkim={auth}; dmarc={auth}"
    )
    msg["X-PhishScope-Simulation"] = "true"
    if reply:
        msg["Reply-To"] = reply
    msg.set_content("SIMULATION ONLY. " + body)
    if key == "account":
        msg.add_alternative(
            '<p>SIMULATION ONLY. Urgent: verify your account password to prevent suspension.</p><a href="https://verify-account.example/login?redirect=https%3A%2F%2Flanding.example">https://microsoft.example/security</a><span style="display:none"><a href="https://hidden.example/track">hidden link</a></span>',
            subtype="html",
        )
    if attachment:
        msg.add_attachment(
            b"INERT SIMULATION TEXT; NOT AN EXECUTABLE",
            maintype="application",
            subtype="pdf",
            filename="Invoice.pdf.exe",
        )
    return {
        "id": key,
        "name": title,
        "description": subject,
        "raw_email": msg.as_string(),
        "simulation": True,
    }


SAMPLES = [
    sample(
        "account",
        "Account security phishing",
        "Microsoft Security <security@verify-account.example>",
        "Urgent: verify your account or face suspension",
        "Verify your password immediately at https://verify-account.example/login",
        "help@support-desk.example",
    ),
    sample(
        "invoice",
        "Invoice fraud",
        "Finance Department <billing@vendor-payments.example>",
        "Urgent overdue invoice: payment required",
        "Please open the attached invoice and pay immediately. New bank details attached.",
        "accounts@other-payments.example",
        attachment=True,
    ),
    sample(
        "delivery",
        "Delivery notification phishing",
        "Parcel Service <notice@parcel-notice.example>",
        "Final warning: delivery failed, action required",
        "Pay the redelivery fee immediately: https://short.example/p/7x?url=https%3A%2F%2Fparcel-fees.example",
        "help@parcel-help.example",
    ),
    sample(
        "benign",
        "Legitimate business email",
        "Taylor Morgan <taylor@company.example>",
        "Project planning meeting on Friday",
        "Hi team, the project planning meeting is on Friday at 10:00. The agenda covers milestones and resourcing. Thanks, Taylor.",
        auth="pass",
    ),
]
