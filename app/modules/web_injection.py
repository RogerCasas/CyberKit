"""
CyberKit — Shared web parameter-injection helper.

Used by the SQL Injection Tester, XSS Tester, and Open Redirect Detector to
parse query parameters and build a GET/POST request with a single parameter
replaced by a payload. Keeping this in one place means all three modules inject
identically and there is a single implementation to test and reason about.
"""

from urllib.parse import urlparse, urlencode, parse_qs


def parse_params(url: str) -> list:
    """Return the list of query-string parameter names in *url* (may be empty)."""
    return list(parse_qs(urlparse(url).query).keys())


def inject(url: str, method: str, param: str, payload: str) -> dict:
    """
    Replace *param* with *payload* and return ``{"url": ..., "body": ...}``.

    GET  → payload goes in the query string, body is empty.
    POST → all params move to a urlencoded body, query string is cleared.

    All other parameters are preserved.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]

    if method.upper() == "GET":
        new_query = urlencode(qs, doseq=True)
        return {"url": parsed._replace(query=new_query).geturl(), "body": ""}
    else:
        flat = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
        return {"url": parsed._replace(query="").geturl(), "body": urlencode(flat)}
