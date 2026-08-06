"""Tests for telemetry secret redaction."""

from composio.utils.redaction import redact_sensitive_text


def test_redacts_url_queries_authorization_and_secret_pairs() -> None:
    redacted = redact_sensitive_text(
        "https://example.com/file?signature=secret Bearer token123 api_key=abc password: hunter2"
    )

    assert "signature=secret" not in redacted
    assert "token123" not in redacted
    assert "api_key=abc" not in redacted
    assert "password: hunter2" not in redacted
    assert redacted.count("[REDACTED]") == 4


def test_redacts_json_shaped_secret_pairs() -> None:
    """Secrets in JSON payloads (quoted keys) must be redacted.

    Stack traces and error messages -- the exact strings this helper runs on
    before telemetry upload -- routinely embed JSON request/response bodies, so
    a quoted key like ``"password"`` must not slip the secret through.
    """
    redacted = redact_sensitive_text('{"password": "hunter2", "api_key":"sk-abc123"}')

    assert "hunter2" not in redacted
    assert "sk-abc123" not in redacted
    assert redacted.count("[REDACTED]") == 2
    # Surrounding JSON structure is preserved.
    assert redacted == '{"password": "[REDACTED]", "api_key":"[REDACTED]"}'


def test_redacts_python_dict_repr_secret_pairs() -> None:
    """Secrets in Python dict reprs (single-quoted) must be redacted too."""
    redacted = redact_sensitive_text("config = {'client_secret': 'topsecret'}")

    assert "topsecret" not in redacted
    assert redacted == "config = {'client_secret': '[REDACTED]'}"


def test_does_not_redact_secret_word_without_assignment() -> None:
    """A key word that is not part of a key/value pair is left untouched."""
    text = "the secret is out and the password was never set"
    assert redact_sensitive_text(text) == text
