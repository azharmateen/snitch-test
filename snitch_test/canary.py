"""Generate realistic-looking but trackable fake credentials."""

import hashlib
import secrets
import string
import time
from dataclasses import dataclass, field


@dataclass
class CanaryCredential:
    """A fake credential that can be tracked if exfiltrated."""
    name: str
    value: str
    category: str
    description: str
    fingerprint: str = field(default="")

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = hashlib.sha256(
                f"{self.name}:{self.value}".encode()
            ).hexdigest()[:16]


def _random_hex(length: int) -> str:
    return secrets.token_hex(length // 2)


def _random_b64(length: int) -> str:
    return secrets.token_urlsafe(length)[:length]


def _random_alphanum(length: int) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def generate_canary_set(session_id: str | None = None) -> list[CanaryCredential]:
    """Generate a complete set of canary credentials.

    All values look realistic but contain an embedded session marker
    so leaked values can be traced back to this specific scan.
    """
    sid = session_id or secrets.token_hex(4)
    ts = hex(int(time.time()))[2:]

    canaries = [
        # AWS credentials
        CanaryCredential(
            name="AWS_ACCESS_KEY_ID",
            value=f"AKIA{_random_alphanum(16).upper()}",
            category="cloud",
            description="AWS access key ID",
        ),
        CanaryCredential(
            name="AWS_SECRET_ACCESS_KEY",
            value=f"{_random_b64(40)}",
            category="cloud",
            description="AWS secret access key",
        ),
        CanaryCredential(
            name="AWS_SESSION_TOKEN",
            value=f"FwoGZXIvYXdzE{_random_b64(120)}",
            category="cloud",
            description="AWS session token",
        ),

        # Database URLs
        CanaryCredential(
            name="DATABASE_URL",
            value=f"postgresql://admin:{_random_alphanum(20)}@db-{sid}.internal:5432/production",
            category="database",
            description="PostgreSQL connection string",
        ),
        CanaryCredential(
            name="REDIS_URL",
            value=f"redis://:{_random_alphanum(24)}@cache-{sid}.internal:6379/0",
            category="database",
            description="Redis connection string",
        ),
        CanaryCredential(
            name="MONGODB_URI",
            value=f"mongodb+srv://admin:{_random_alphanum(20)}@cluster-{sid}.mongodb.net/prod?retryWrites=true",
            category="database",
            description="MongoDB connection string",
        ),

        # API tokens
        CanaryCredential(
            name="OPENAI_API_KEY",
            value=f"sk-{_random_alphanum(48)}",
            category="api",
            description="OpenAI API key",
        ),
        CanaryCredential(
            name="STRIPE_SECRET_KEY",
            value=f"sk_live_{_random_alphanum(24)}",
            category="api",
            description="Stripe secret key",
        ),
        CanaryCredential(
            name="SENDGRID_API_KEY",
            value=f"SG.{_random_b64(22)}.{_random_b64(43)}",
            category="api",
            description="SendGrid API key",
        ),
        CanaryCredential(
            name="TWILIO_AUTH_TOKEN",
            value=_random_hex(32),
            category="api",
            description="Twilio authentication token",
        ),
        CanaryCredential(
            name="GITHUB_TOKEN",
            value=f"ghp_{_random_alphanum(36)}",
            category="api",
            description="GitHub personal access token",
        ),
        CanaryCredential(
            name="SLACK_BOT_TOKEN",
            value=f"xoxb-{secrets.randbelow(10**12)}-{secrets.randbelow(10**13)}-{_random_alphanum(24)}",
            category="api",
            description="Slack bot token",
        ),

        # Encryption/signing
        CanaryCredential(
            name="SECRET_KEY",
            value=_random_b64(64),
            category="crypto",
            description="Application secret key",
        ),
        CanaryCredential(
            name="JWT_SECRET",
            value=_random_b64(48),
            category="crypto",
            description="JWT signing secret",
        ),
        CanaryCredential(
            name="ENCRYPTION_KEY",
            value=_random_hex(64),
            category="crypto",
            description="Data encryption key",
        ),

        # Cloud provider
        CanaryCredential(
            name="GOOGLE_APPLICATION_CREDENTIALS_JSON",
            value=(
                '{"type":"service_account","project_id":"canary-' + sid + '",'
                '"private_key_id":"' + _random_hex(20) + '",'
                '"private_key":"-----BEGIN RSA PRIVATE KEY-----\\nMIIE' + _random_b64(60) + '\\n-----END RSA PRIVATE KEY-----\\n",'
                '"client_email":"canary@canary-' + sid + '.iam.gserviceaccount.com"}'
            ),
            category="cloud",
            description="Google Cloud service account JSON",
        ),
        CanaryCredential(
            name="AZURE_CLIENT_SECRET",
            value=f"{_random_b64(40)}",
            category="cloud",
            description="Azure AD client secret",
        ),

        # SSH / Private keys
        CanaryCredential(
            name="SSH_PRIVATE_KEY",
            value=f"-----BEGIN OPENSSH PRIVATE KEY-----\n{_random_b64(70)}\n{_random_b64(70)}\n-----END OPENSSH PRIVATE KEY-----",
            category="crypto",
            description="SSH private key",
        ),

        # SMTP
        CanaryCredential(
            name="SMTP_PASSWORD",
            value=_random_alphanum(16),
            category="email",
            description="SMTP password",
        ),
    ]

    return canaries


def canary_values_set(canaries: list[CanaryCredential]) -> set[str]:
    """Extract the set of all canary values for matching."""
    values = set()
    for c in canaries:
        values.add(c.value)
        # Also add substrings that might appear in partial exfiltration
        if len(c.value) > 20:
            values.add(c.value[:20])
    return values


def find_canary_in_text(text: str, canaries: list[CanaryCredential]) -> list[CanaryCredential]:
    """Find which canary values appear in a given text."""
    found = []
    for c in canaries:
        if c.value in text:
            found.append(c)
        elif len(c.value) > 20 and c.value[:20] in text:
            found.append(c)
    return found
