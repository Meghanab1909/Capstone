import json
import re
from gateway import log_event, extract_path_features


def test_log_event_decision_reflects_pool_not_label(tmp_path, monkeypatch):
    """Regression test: decision must reflect actual routing (pool), not the
    raw label — this is the exact bug found where a forced-demo hit logged
    'allow' even though it was routed to the honeypot."""
    monkeypatch.setattr("gateway.GATEWAY_LOG", str(tmp_path / "gateway.log"))
    log_event(req_id=1, src_ip="127.0.0.1", label=0,
              target="http://127.0.0.1:5002", cluster_idx=0, pool="honeypot")
    entry = json.loads((tmp_path / "gateway.log").read_text().strip())
    assert entry["ai_label"] == "benign"
    assert entry["decision"] == "redirect"


def test_log_event_benign_case(tmp_path, monkeypatch):
    """A genuinely benign request (label=0, routed to real pool) must log
    ai_label=benign and decision=allow, with no cross-contamination between
    the two fields."""
    monkeypatch.setattr("gateway.GATEWAY_LOG", str(tmp_path / "gateway.log"))
    log_event(req_id=2, src_ip="127.0.0.1", label=0,
              target="http://127.0.0.1:5000", cluster_idx=0, pool="real")
    entry = json.loads((tmp_path / "gateway.log").read_text().strip())
    assert entry["ai_label"] == "benign"
    assert entry["decision"] == "allow"


def test_extract_path_features_detects_sqli():
    """SQL injection payloads in the query string must set has_sql_pattern."""
    features = extract_path_features("/search?q=1' OR '1'='1", b"")
    assert features["has_sql_pattern"] == 1
    assert features["has_xss_pattern"] == 0


def test_extract_path_features_detects_traversal():
    """Directory traversal sequences (../) must set has_traversal_pattern."""
    features = extract_path_features("/api/v1/../../etc/passwd", b"")
    assert features["has_traversal_pattern"] == 1


def test_extract_path_features_detects_xss():
    """Script-tag injection in the request body must set has_xss_pattern."""
    features = extract_path_features("/comment", b"msg=<script>alert(1)</script>")
    assert features["has_xss_pattern"] == 1


def test_extract_path_features_detects_rce():
    """Shell command injection in the request body must set has_rce_pattern."""
    features = extract_path_features("/api/ping", b"host=127.0.0.1; cat /etc/passwd")
    assert features["has_rce_pattern"] == 1


def test_extract_path_features_detects_recon_cve():
    """Known CVE-probe / recon paths (e.g. .env, .git/config) must set
    has_recon_cve_pattern."""
    features = extract_path_features("/.env", b"")
    assert features["has_recon_cve_pattern"] == 1


def test_extract_path_features_benign_path_has_no_flags():
    """An ordinary, non-malicious path must set ALL pattern flags to 0 —
    the negative case, just as important as detecting real attacks."""
    features = extract_path_features("/status", b"")
    assert features["has_sql_pattern"] == 0
    assert features["has_xss_pattern"] == 0
    assert features["has_traversal_pattern"] == 0
    assert features["has_rce_pattern"] == 0
    assert features["has_recon_cve_pattern"] == 0


def test_force_suspicious_query_param_parsing():
    """The _force_suspicious=1 query param must be correctly recognized —
    this is the exact mechanism the Simulate button on the portal relies on."""
    from urllib.parse import urlparse, parse_qs
    path = "/api/pipeline-stream?_force_suspicious=1&_sim_path=%2Fstatus"
    qs = parse_qs(urlparse(path).query)
    assert qs.get("_force_suspicious", ["0"])[0] == "1"


def test_clean_path_strips_force_suspicious_param():
    """clean_path must strip the _force_suspicious=1 test-only param so it
    never leaks into the honeypot's LLM analysis narrative as if a real
    attacker had sent it."""
    raw_path = "/search?q=test&_force_suspicious=1"
    clean = re.sub(r"([?&])_force_suspicious=1&?", r"\1", raw_path).rstrip("?&")
    assert "_force_suspicious" not in clean
    assert clean == "/search?q=test"
