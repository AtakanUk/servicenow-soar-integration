"""Alert profiles: what to look up in QRadar and what to tell the user.

Each profile lists the event properties to collect from the offense (one AQL
query per property, grouped so every distinct value is returned once), how to
store them as SOAR artifacts, and the notification text that ServiceNow sends
to the affected user. Template placeholders are filled from the collected
values plus ``{event_time}`` and ``{offense_id}``; values are HTML-escaped.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EventField:
    key: str  # placeholder / result key
    aql_property: str  # QRadar property or column, e.g. "sourceip" or "M365 Defender UPN"
    artifact_type: str
    artifact_description: str
    ip_role: str | None = None  # "source" / "destination" for IP artifacts


@dataclass(frozen=True)
class AlertProfile:
    name: str
    short_description: str
    fields: tuple[EventField, ...]
    template: str
    recipient_key: str = "user_email"
    defaults: dict[str, str] = field(default_factory=dict)


SOURCE_IP = EventField("source_ip", "sourceip", "IP Address", "Source IP Address", ip_role="source")
USERNAME = EventField("username", "M365 Defender Account Name", "User Account", "QRadar: Username")
USER_EMAIL = EventField("user_email", "M365 Defender UPN", "Email Recipient", "QRadar: User email")
COUNTRY = EventField(
    "country", "MS365 Defender Country Letter Code", "String", "QRadar: Country code"
)
ADDITIONAL_DETAIL = EventField(
    "additional_detail", "Additional Detail", "String", "QRadar: Additional detail"
)
USER_AGENT = EventField("user_agent", "User Agent", "String", "QRadar: User agent")

_CLOSING = """
<p>If you have any questions about this notification or need help, please contact the Information Security team.</p>
<p>Best regards,<br>Information Security Team</p>
"""

ATYPICAL_TRAVEL = AlertProfile(
    name="atypical_travel",
    short_description="Atypical Travel Detected",
    fields=(SOURCE_IP, USERNAME, USER_EMAIL, COUNTRY),
    template="""<p>Dear {username},</p>
<p><b>Why do you get this email?</b><br>
A sign-in to your account was detected from <b>{country}</b> (IP address {source_ip}), a location that does not match your
recent sign-in history. Two sign-ins from distant locations within a short time may mean that someone else is using
your credentials. A VPN service on your device can also cause this alert.</p>
<p><b>What do I have to do?</b><br>
&bull; If you are travelling or using a remote connection that explains this activity, report the alert as acknowledged.<br>
&bull; If the activity is unfamiliar, change your password immediately, make sure MFA is enabled and contact the Information Security team.</p>
<p><b>Observation details</b><br>
&bull; Time: {event_time}<br>&bull; Username: {username}<br>&bull; Location: {country}<br>&bull; IP address: {source_ip}</p>
"""
    + _CLOSING,
)

PASSWORD_SPRAY = AlertProfile(
    name="password_spray",
    short_description="Password Spray Attack Detected",
    fields=(SOURCE_IP, USERNAME, USER_EMAIL, COUNTRY),
    template="""<p>Dear {username},</p>
<p><b>Why do you get this email?</b><br>
Your account was targeted by a password spray attack: repeated sign-in attempts with commonly used passwords, spread
across many accounts to avoid lockouts. The activity originated from <b>{country}</b> (IP address {source_ip}). Even if
the attempts were unsuccessful, your account was actively targeted.</p>
<p><b>What do I have to do?</b><br>
&bull; If this matches known activity or testing, report the alert as acknowledged.<br>
&bull; Otherwise change your password immediately and report the incident to the Information Security team.</p>
<p><b>Observation details</b><br>
&bull; Time: {event_time}<br>&bull; Username: {username}<br>&bull; Location: {country}</p>
"""
    + _CLOSING,
)

MALICIOUS_URL_CLICK = AlertProfile(
    name="malicious_url_click",
    short_description="Malicious Link Click Detected",
    fields=(ADDITIONAL_DETAIL, USER_AGENT),
    recipient_key="user_email",
    defaults={"sender": "an external sender"},
    template="""<p>Dear {user_email},</p>
<p><b>Why do you get this email?</b><br>
An email from <i>{sender}</i> containing a link classified as malicious was delivered to your mailbox, and the link was
clicked from your account. Malicious links can lead to malware infection, credential theft or unauthorized access.</p>
<p><b>What do I have to do?</b><br>
&bull; If you recognize the email and opened the link intentionally as part of expected activity, report the alert as acknowledged.<br>
&bull; Otherwise do not interact with the message any further and report it to the Information Security team.</p>
<p><b>Observation details</b><br>
&bull; Time: {event_time}<br>&bull; Recipient: {user_email}<br>&bull; Details: {additional_detail}<br>&bull; Browser: {user_agent}</p>
"""
    + _CLOSING,
)

MFA_FRAUD = AlertProfile(
    name="mfa_fraud",
    short_description="MFA Fraud Alert",
    fields=(ADDITIONAL_DETAIL, USER_AGENT),
    template="""<p>Dear {user_email},</p>
<p><b>Why do you get this email?</b><br>
A multi-factor authentication request for your account was denied and reported as fraud in the authenticator app.
This usually means that someone else knows your password and tried to sign in.</p>
<p><b>What do I have to do?</b><br>
&bull; If you reported the request yourself, change your password now; the attacker already has it.<br>
&bull; If you did not, contact the Information Security team immediately.</p>
<p><b>Observation details</b><br>
&bull; Time: {event_time}<br>&bull; Details: {additional_detail}<br>&bull; Client: {user_agent}</p>
"""
    + _CLOSING,
)

PROFILES = {
    profile.name: profile
    for profile in (ATYPICAL_TRAVEL, PASSWORD_SPRAY, MALICIOUS_URL_CLICK, MFA_FRAUD)
}
