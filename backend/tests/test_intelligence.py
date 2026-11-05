import httpx
import pytest
from backend.intelligence import lookup, public_indicator


@pytest.mark.parametrize(
    "value,kind",
    [
        ("192.168.0.1", "ipv4"),
        ("192.0.2.1", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("a@x.com", "email"),
        ("foo.example", "domain"),
        ("https://example.com/", "url"),
        ("https://public.com/?token=private", "url"),
        ("https://user:pass@public.com/", "url"),
        ("https://localhost/a", "url"),
        ("evil.local", "domain"),
    ],
)
def test_private_or_sensitive_indicators_blocked(value, kind):
    assert not public_indicator(value, kind)


def test_missing_credentials_truthful(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    result = lookup("virustotal", "8.8.8.8", "ipv4")
    assert result["status"] == "not_configured"
    assert result["reputation"] == "unverified"
    assert result["detections"] is None


@pytest.mark.parametrize(
    "status,expected",
    [(429, "rate_limited"), (500, "error"), (401, "unauthorized"), (404, "no_record")],
)
def test_http_failures(monkeypatch, status, expected):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")

    def get(*args, **kwargs):
        return httpx.Response(
            status, json={}, request=httpx.Request("GET", "https://www.virustotal.com")
        )

    monkeypatch.setattr(httpx.Client, "get", get)
    r = lookup("virustotal", "8.8.8.8", "ipv4")
    assert r["status"] == expected
    assert r["reputation"] == "unverified"


def test_timeout(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")

    def get(*args, **kwargs):
        raise httpx.ReadTimeout("timeout")

    monkeypatch.setattr(httpx.Client, "get", get)
    assert lookup("virustotal", "8.8.8.8", "ipv4")["status"] == "error"


@pytest.mark.parametrize(
    "provider,kind,value,payload,expected",
    [
        (
            "virustotal",
            "ipv4",
            "8.8.8.8",
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 2, "harmless": 7}
                    }
                }
            },
            "malicious",
        ),
        (
            "abuseipdb",
            "ipv4",
            "8.8.8.8",
            {"data": {"abuseConfidenceScore": 70, "totalReports": 4}},
            "reported_abuse",
        ),
        ("urlscan", "domain", "public.com", {"results": [], "total": 0}, "unverified"),
        (
            "safebrowsing",
            "url",
            "https://public.com/",
            {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]},
            "malicious",
        ),
    ],
)
def test_provider_adapters_using_explicit_test_doubles(
    monkeypatch, provider, kind, value, payload, expected
):
    from backend.intelligence import PROVIDERS

    monkeypatch.setenv(PROVIDERS[provider], "dummy")

    def request(*args, **kwargs):
        return httpx.Response(
            200, json=payload, request=httpx.Request("GET", "https://provider.test")
        )

    monkeypatch.setattr(httpx.Client, "get", request)
    monkeypatch.setattr(httpx.Client, "post", request)
    result = lookup(provider, value, kind)
    assert result["status"] == "ok"
    assert result["reputation"] == expected
