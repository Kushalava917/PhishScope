"""Read-only lookups against fixed provider endpoints. Never visit indicator URLs."""

import base64
import ipaddress
import os
import re
from urllib.parse import quote, urlsplit

import httpx

from .analysis import now

PROVIDERS = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "safebrowsing": "GOOGLE_SAFE_BROWSING_API_KEY",
}


def public_indicator(value, kind):
    # Deny synthetic, internal, user-info and query-bearing URLs to reduce disclosure.
    if kind in {"md5", "sha1", "sha256"}:
        return bool(
            re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value)
        )
    if kind in {"ipv4", "ipv6"}:
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return False
    if kind not in {"url", "domain"}:
        return False
    try:
        parsed = urlsplit(value) if kind == "url" else None
        host = parsed.hostname if parsed else value
        if parsed and (
            parsed.scheme not in {"https", "http"}
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.port not in {None, 80, 443}
        ):
            return False
        if (
            not host
            or "." not in host
            or host.lower().endswith(
                (
                    ".example",
                    ".test",
                    ".invalid",
                    ".localhost",
                    ".local",
                    ".internal",
                    ".home",
                    ".arpa",
                    ".lan",
                )
            )
            or host in {"example.com", "example.net", "example.org"}
            or host.endswith((".example.com", ".example.net", ".example.org"))
        ):
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return bool(re.fullmatch(r"[a-zA-Z0-9.-]+", host))
    except ValueError:
        return False


def lookup(provider, value, kind):
    result = {
        "provider": provider,
        "indicator": value,
        "checked_at": now(),
        "status": "unavailable",
        "reputation": "unverified",
        "source_url": None,
        "detections": None,
    }
    if not public_indicator(value, kind):
        return {
            **result,
            "status": "blocked",
            "message": "Only public indicators are allowed. Reserved/internal values, email addresses and URLs containing queries, fragments or credentials are excluded.",
        }
    key = os.getenv(PROVIDERS[provider], "")
    if not key:
        return {
            **result,
            "status": "not_configured",
            "message": "Provider key is not configured. Local heuristic assessment — not externally verified.",
        }
    try:
        with httpx.Client(
            timeout=10, follow_redirects=False, trust_env=False
        ) as client:
            if provider == "virustotal":
                endpoint = (
                    "domains"
                    if kind == "domain"
                    else "ip_addresses"
                    if kind in {"ipv4", "ipv6"}
                    else "files"
                    if kind in {"md5", "sha1", "sha256"}
                    else "urls"
                )
                target = (
                    base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
                    if kind == "url"
                    else value
                )
                response = client.get(
                    f"https://www.virustotal.com/api/v3/{endpoint}/{quote(target, safe='')}",
                    headers={"x-apikey": key},
                )
            elif provider == "abuseipdb":
                if kind not in {"ipv4", "ipv6"}:
                    return {
                        **result,
                        "status": "unsupported",
                        "message": "AbuseIPDB supports IP addresses only.",
                    }
                response = client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": value, "maxAgeInDays": 90},
                    headers={"Key": key, "Accept": "application/json"},
                )
            elif provider == "urlscan":
                if kind not in {"url", "domain", "ipv4", "ipv6"}:
                    return {
                        **result,
                        "status": "unsupported",
                        "message": "URLScan search supports domains, URLs and IPs.",
                    }
                field = (
                    "page.url"
                    if kind == "url"
                    else "domain"
                    if kind == "domain"
                    else "ip"
                )
                escaped = value.replace("\\", "\\\\").replace('"', '\\"')
                response = client.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": f'{field}:"{escaped}"', "size": 10},
                    headers={"api-key": key},
                )
            else:
                if kind != "url":
                    return {
                        **result,
                        "status": "unsupported",
                        "message": "Safe Browsing supports URLs only.",
                    }
                response = client.post(
                    "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                    params={"key": key},
                    json={
                        "client": {"clientId": "phishscope", "clientVersion": "1.0.0"},
                        "threatInfo": {
                            "threatTypes": [
                                "MALWARE",
                                "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE",
                            ],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": value}],
                        },
                    },
                )
        if response.status_code == 429:
            return {
                **result,
                "status": "rate_limited",
                "message": "Provider rate limit reached; try again later.",
                "retry_after": response.headers.get("Retry-After", "unknown"),
            }
        if response.status_code == 404:
            return {
                **result,
                "status": "no_record",
                "message": "No existing provider record; no scan was submitted.",
            }
        if response.status_code in {401, 403}:
            return {
                **result,
                "status": "unauthorized",
                "message": "Provider rejected the credentials or subscription permissions.",
            }
        response.raise_for_status()
        data = response.json()
        result.update(
            status="ok",
            message="Existing provider data retrieved; no content or attachment was submitted.",
        )
        if provider == "virustotal":
            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            if not stats:
                raise ValueError("Missing analysis statistics")
            result.update(
                detections=stats,
                reputation="malicious"
                if stats.get("malicious", 0) > 0
                else "no_detections",
                source_url=f"https://www.virustotal.com/gui/{'domain' if kind == 'domain' else 'ip-address' if kind in {'ipv4', 'ipv6'} else 'file' if kind in {'md5', 'sha1', 'sha256'} else 'url'}/{quote(target, safe='')}",
            )
        elif provider == "abuseipdb":
            score = data["data"]["abuseConfidenceScore"]
            result.update(
                detections={
                    "abuseConfidenceScore": score,
                    "totalReports": data["data"].get("totalReports"),
                },
                reputation="reported_abuse" if score else "no_detections",
                source_url=f"https://www.abuseipdb.com/check/{quote(value, safe='')}",
            )
        elif provider == "urlscan":
            records = data["results"]
            result.update(
                detections={
                    "existing_records": len(records),
                    "total": data.get("total"),
                },
                reputation="unverified",
                source_url="https://urlscan.io/search/",
            )
        else:
            matches = data.get("matches", [])
            result.update(
                detections={"matches": [m.get("threatType") for m in matches]},
                reputation="malicious" if matches else "no_detections",
                source_url="https://transparencyreport.google.com/safe-browsing/search",
            )
        return result
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return {
            **result,
            "status": "error",
            "message": "Provider request failed or returned an unexpected response. No external reputation conclusion was made.",
        }
