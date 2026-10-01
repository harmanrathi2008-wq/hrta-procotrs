"""
HRTA Cloud Proctoring Engine — Security & Defense-in-Depth Verification Suite
Tests:
1. 403 Forbidden on direct browser navigation (Accept: text/html)
2. Cloudflare Edge Shield (Tier A secret token + Tier B CF headers fallback)
3. Direct-to-origin blocking when CF headers and secret token are missing
4. Host header validation & poisoning defense
5. Cryptographic HMAC-SHA256 session token verification
6. In-memory sliding window rate limiter
"""

import time
import hmac
import hashlib
from core.security import (
    build_forbidden_html_page,
    is_direct_browser_request,
    verify_cloudflare_edge_shield,
    is_valid_host,
    is_valid_origin,
    check_rate_limit,
    verify_exam_session_token
)
from core.config import settings

def run_all_tests():
    passed = 0
    total = 0

    def assert_test(name, condition, msg=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name}: {msg}")

    print("=================================================================")
    print("RUNNING HRTA PROCTOR SUBDOMAIN SECURITY VERIFICATION SUITE")
    print("=================================================================")

    # 1. Direct Browser Navigation Detection
    assert_test(
        "1a: Direct browser request with 'text/html' triggers WAF block",
        is_direct_browser_request({"accept": "text/html,application/xhtml+xml,application/xml;q=0.9"}) is True
    )
    assert_test(
        "1b: Browser navigation mode (sec-fetch-mode: navigate) triggers WAF block",
        is_direct_browser_request({"sec-fetch-mode": "navigate", "sec-fetch-dest": "document"}) is True
    )
    assert_test(
        "1c: Legitimate API client (application/json) is NOT flagged as browser navigation",
        is_direct_browser_request({"accept": "application/json", "content-type": "application/json"}) is False
    )

    # 2. 403 WAF HTML Gate Page Generation
    html_page = build_forbidden_html_page("103.21.244.15", "ray-test-12345", "Direct Browser Probing Forbidden")
    assert_test("2a: WAF HTML page contains 403 Forbidden title", "<title>403 Forbidden — Security Protection Gateway</title>" in html_page)
    assert_test("2b: WAF HTML page contains Client IP", "103.21.244.15" in html_page)
    assert_test("2c: WAF HTML page contains Ray ID", "ray-test-12345" in html_page)
    assert_test("2d: WAF HTML page contains HRTA Edge Shield watermark", "HRTA Edge Shield" in html_page)

    # 3. Cloudflare Edge Shield Enforcement
    # In test, temporarily override environment to production
    settings.ENVIRONMENT = "production"
    settings.CLOUDFLARE_SECRET_TOKEN = "secret_cf_token_xyz987"

    # Direct-to-origin attempt: no CF headers, no secret token
    ok, reason = verify_cloudflare_edge_shield({}, "/api/v1/proctor/inspect", "192.168.1.50")
    assert_test("3a: Direct-to-origin request without CF headers or token is blocked (Tier C)", ok is False)

    # Cloudflare headers alone are not authentication.
    cf_headers = {"cf-connecting-ip": "103.21.244.15", "cf-ray": "89abc123-BOM"}
    ok_b, _ = verify_cloudflare_edge_shield(cf_headers, "/api/v1/proctor/inspect", "103.21.244.15")
    assert_test("3b: Cloudflare headers without the edge secret are rejected", ok_b is False)

    # Tier A: Secret token present
    secret_headers = {"x-render-secret": "secret_cf_token_xyz987"}
    ok_a, _ = verify_cloudflare_edge_shield(secret_headers, "/api/v1/proctor/inspect", "192.168.1.50")
    assert_test("3c: Request with authentic Cloudflare Transform Rule token passes (Tier A)", ok_a is True)

    # Wrong secret token
    bad_headers = {"x-render-secret": "wrong_secret_attacker"}
    ok_bad, _ = verify_cloudflare_edge_shield(bad_headers, "/api/v1/proctor/inspect", "192.168.1.50")
    assert_test("3d: Forged/invalid edge secret token is strictly rejected", ok_bad is False)

    # Health check exemption
    ok_health, _ = verify_cloudflare_edge_shield({}, "/health", "192.168.1.50")
    assert_test("3e: Health check endpoint /health is exempt for uptime monitoring", ok_health is True)

    # 4. Host Header Validation
    assert_test("4a: Canonical subdomain proctor.hrtacbt.in is allowed", is_valid_host("proctor.hrtacbt.in") is True)
    settings.RENDER_HOSTNAME = "hrta-proctor-engine.onrender.com"
    assert_test("4b: Configured Render app domain is allowed during deployment verification", is_valid_host("hrta-proctor-engine.onrender.com") is True)
    assert_test("4c: Unconfigured Render app domain is rejected", is_valid_host("other-service.onrender.com") is False)
    assert_test("4d: Untrusted host header (attacker.com) is rejected", is_valid_host("attacker.evil.com") is False)

    # 5. Cross-Origin Validation
    assert_test("5a: Official portal origin https://hrtacbt.in is allowed", is_valid_origin("https://hrtacbt.in") is True)
    assert_test("5b: Official portal subdomain https://api.hrtacbt.in is allowed", is_valid_origin("https://api.hrtacbt.in") is True)
    assert_test("5c: Rogue origin https://phishing-cbt.com is blocked", is_valid_origin("https://phishing-cbt.com") is False)

    # 6. Cryptographic Exam Session Token Verification
    settings.SUPER_ADMIN_SECRET = "super_test_secret_key_12345"
    now_ms = int(time.time() * 1000)
    sig = hmac.new(
        b"super_test_secret_key_12345",
        f"exam_101:student_202:{now_ms}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    valid_token = f"exam_101.student_202.{now_ms}.{sig}"

    tok_ok, msg = verify_exam_session_token(valid_token, "exam_101", "student_202")
    assert_test("6a: Valid cryptographic exam session token passes", tok_ok is True)

    forged_token = f"exam_101.student_202.{now_ms}.badsignature123456"
    forged_ok, _ = verify_exam_session_token(forged_token, "exam_101", "student_202")
    assert_test("6b: Tampered/forged token signature is detected and rejected", forged_ok is False)

    expired_ms = now_ms - (25 * 60 * 60 * 1000)  # 25 hours ago
    exp_sig = hmac.new(b"super_test_secret_key_12345", f"exam_101:student_202:{expired_ms}".encode("utf-8"), hashlib.sha256).hexdigest()
    expired_token = f"exam_101.student_202.{expired_ms}.{exp_sig}"
    exp_ok, _ = verify_exam_session_token(expired_token, "exam_101", "student_202")
    assert_test("6c: Expired token (>24 hours) is rejected", exp_ok is False)

    # 7. In-Memory Sliding Window Rate Limiter
    test_ip = "198.51.100.77"
    settings.MAX_REQUESTS_PER_MINUTE = 5
    for _ in range(5):
        check_rate_limit(test_ip)
    assert_test("7: Rapid request flood exceeding threshold is rate limited", check_rate_limit(test_ip) is False)

    print("=================================================================")
    print(f"SECURITY TEST RESULTS: {passed}/{total} PASSED")
    print("=================================================================")

    if passed != total:
        exit(1)

if __name__ == "__main__":
    run_all_tests()
