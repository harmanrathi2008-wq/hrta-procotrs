import time
import hmac
import hashlib
import re
import secrets
from typing import Tuple, Optional, Dict, List
from .config import settings

MONITORING_ENDPOINT_PATH = "/internal/monitor"

# Rate Limiter State (In-Memory Sliding Window)
_rate_limit_records: Dict[str, List[float]] = {}
_last_cleanup_time: float = time.time()


def build_forbidden_html_page(client_ip: str, ray_id: str, reason: str = "Access Denied — Edge Security Policy Violation") -> str:
    """
    Renders an enterprise-grade dark-theme 403 Forbidden WAF page.
    Identical to the HRTA CBT Central Controller WAF gate, preventing backend
    fingerprinting and blocking unauthorized direct browser exploration.
    """
    timestamp = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>403 Forbidden — Security Protection Gateway</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background-color: #0b0f19;
    color: #cbd5e1;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }}
  .container {{
    max-width: 620px;
    width: 100%;
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 40px;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
  }}
  .header {{
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 24px;
    padding-bottom: 20px;
    border-bottom: 1px solid #1e293b;
  }}
  .icon-wrapper {{
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.2);
    border-radius: 10px;
    width: 52px;
    height: 52px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #ef4444;
    font-size: 24px;
  }}
  .title-group h1 {{
    font-size: 20px;
    font-weight: 700;
    color: #f8fafc;
    letter-spacing: -0.02em;
  }}
  .title-group p {{
    font-size: 13px;
    color: #64748b;
    margin-top: 2px;
  }}
  .content {{
    font-size: 14px;
    line-height: 1.6;
    color: #94a3b8;
    margin-bottom: 28px;
  }}
  .details-box {{
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 16px 20px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
    color: #94a3b8;
    margin-bottom: 24px;
  }}
  .details-row {{
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px dashed #1e293b;
  }}
  .details-row:last-child {{
    border-bottom: none;
  }}
  .label {{ color: #64748b; }}
  .val {{ color: #e2e8f0; font-weight: 600; }}
  .val-danger {{ color: #f87171; font-weight: 600; }}
  .footer {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 12px;
    color: #475569;
    border-top: 1px solid #1e293b;
    padding-top: 20px;
  }}
  .badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(59, 130, 246, 0.1);
    border: 1px solid rgba(59, 130, 246, 0.2);
    color: #60a5fa;
    padding: 4px 10px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 600;
  }}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="icon-wrapper">&#128683;</div>
      <div class="title-group">
        <h1>403 Forbidden</h1>
        <p>Access Denied by Security Edge Policy</p>
      </div>
    </div>
    
    <div class="content">
      Direct requests or unauthorized automated visits to this microservice endpoint are strictly restricted by enterprise firewall rules. If you are an active examination candidate, please access the platform through the official CBT portal application.
    </div>

    <div class="details-box">
      <div class="details-row">
        <span class="label">Reason</span>
        <span class="val-danger">{reason}</span>
      </div>
      <div class="details-row">
        <span class="label">Client IP</span>
        <span class="val">{client_ip}</span>
      </div>
      <div class="details-row">
        <span class="label">Ray ID</span>
        <span class="val">{ray_id}</span>
      </div>
      <div class="details-row">
        <span class="label">Timestamp</span>
        <span class="val">{timestamp}</span>
      </div>
    </div>

    <div class="footer">
      <span>Protected by HRTA Edge Shield</span>
      <span class="badge">&bull; Security Active</span>
    </div>
  </div>
</body>
</html>"""


def build_proctor_landing_page(client_ip: str, ray_id: str) -> str:
    """
    Renders an official, authoritative NTA/HRTA Cloud AI Proctoring Node
    operational status terminal for proctor.hrtacbt.in.
    """
    timestamp = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HRTA Cloud AI Proctoring Node — Operational 24/7</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background-color: #070a13;
    color: #cbd5e1;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }}
  .container {{
    max-width: 680px;
    width: 100%;
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 16px;
    padding: 36px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
  }}
  .badge-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
  }}
  .brand-badge {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(14, 165, 233, 0.1);
    border: 1px solid rgba(14, 165, 233, 0.3);
    color: #38bdf8;
    padding: 6px 12px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .live-indicator {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: #34d399;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
  }}
  .pulse-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #10b981;
    box-shadow: 0 0 10px #10b981;
    animation: pulse 2s infinite;
  }}
  @keyframes pulse {{
    0%, 100% {{ opacity: 1; transform: scale(1); }}
    50% {{ opacity: 0.5; transform: scale(1.2); }}
  }}
  h1 {{
    font-size: 22px;
    font-weight: 800;
    color: #f8fafc;
    letter-spacing: -0.02em;
    margin-bottom: 6px;
  }}
  .subtitle {{
    font-size: 13px;
    color: #94a3b8;
    margin-bottom: 24px;
    line-height: 1.5;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
    margin-bottom: 24px;
  }}
  .card {{
    background: #090e1a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 14px;
  }}
  .card-label {{
    font-size: 11px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
  }}
  .card-value {{
    font-size: 13px;
    font-weight: 700;
    color: #f1f5f9;
  }}
  .card-value.green {{ color: #34d399; }}
  .card-value.cyan {{ color: #38bdf8; }}
  .details-box {{
    background: #090e1a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 14px 18px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
    color: #94a3b8;
    margin-bottom: 24px;
  }}
  .details-row {{
    display: flex;
    justify-content: space-between;
    padding: 5px 0;
    border-bottom: 1px dashed #1e293b;
  }}
  .details-row:last-child {{ border-bottom: none; }}
  .action-btn {{
    display: block;
    width: 100%;
    text-align: center;
    background: linear-gradient(135deg, #0ea5e9 0%, #2563eb 100%);
    color: #ffffff;
    font-weight: 700;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 12px 20px;
    border-radius: 10px;
    text-decoration: none;
    transition: opacity 0.2s;
  }}
  .action-btn:hover {{ opacity: 0.9; }}
  .footer {{
    margin-top: 20px;
    text-align: center;
    font-size: 11px;
    color: #475569;
  }}
</style>
</head>
<body>
  <div class="container">
    <div class="badge-row">
      <span class="brand-badge">HRTA &bull; National Testing Architecture</span>
      <span class="live-indicator"><span class="pulse-dot"></span> Online 24/7</span>
    </div>

    <h1>Autonomous AI Cloud Proctoring Engine</h1>
    <p class="subtitle">
      Dedicated real-time Computer Vision proctoring microservice powering high-integrity NTA standard examinations on <strong>hrtacbt.in</strong>.
    </p>

    <div class="grid">
      <div class="card">
        <div class="card-label">Visual Engine</div>
        <div class="card-value cyan">MediaPipe 3D Pose & Mesh</div>
      </div>
      <div class="card">
        <div class="card-label">Rough Work Tolerance</div>
        <div class="card-value green">75s Calibrated Window</div>
      </div>
      <div class="card">
        <div class="card-label">Edge Shield</div>
        <div class="card-value green">Cloudflare WAF Tier A/B</div>
      </div>
      <div class="card">
        <div class="card-label">Uptime Sentinel</div>
        <div class="card-value green">Keep-Alive 24&times;7 Active</div>
      </div>
    </div>

    <div class="details-box">
      <div class="details-row">
        <span>Endpoint Node</span>
        <span style="color:#f1f5f9; font-weight:600;">proctor.hrtacbt.in</span>
      </div>
      <div class="details-row">
        <span>Your IP Address</span>
        <span style="color:#f1f5f9;">{client_ip}</span>
      </div>
      <div class="details-row">
        <span>Cloudflare Ray ID</span>
        <span style="color:#38bdf8;">{ray_id}</span>
      </div>
      <div class="details-row">
        <span>Server Time</span>
        <span style="color:#94a3b8;">{timestamp}</span>
      </div>
    </div>

    <a href="https://hrtacbt.in" class="action-btn">Launch Official HRTA CBT Portal</a>

    <div class="footer">
      Harman Rathi Testing Agency (HRTA) &bull; National Examination Security Architecture &bull; All Rights Reserved
    </div>
  </div>
</body>
</html>"""


def is_direct_browser_request(headers: Dict[str, str]) -> bool:
    """
    Detects if the incoming request originates from a user directly entering
    the URL into a browser address bar or clicking a link without proper API headers.
    """
    accept = headers.get("accept", "").lower()
    sec_fetch_mode = headers.get("sec-fetch-mode", "").lower()
    sec_fetch_dest = headers.get("sec-fetch-dest", "").lower()

    if "text/html" in accept or "application/xhtml+xml" in accept:
        return True
    if sec_fetch_mode == "navigate" or sec_fetch_dest == "document":
        return True

    return False


def verify_cloudflare_edge_shield(headers: Dict[str, str], path: str, client_ip: str) -> Tuple[bool, str]:
    """
    Multi-tier Cloudflare Edge Shield verification:
    - Tier A: Transform Rule Token match (x-render-secret / x-hrta-edge-secret)
    - Tier B: Cloudflare Provenance fallback (cf-connecting-ip + cf-ray present)
    - Tier C: Missing both -> direct-to-origin probe blocked with 403.
    """
    is_dev = settings.ENVIRONMENT.lower() in ("development", "test")
    is_localhost = client_ip in ("127.0.0.1", "localhost", "::1")
    if is_dev or is_localhost:
        return True, "DEV_BYPASS"

    # Health check path exemption for internal uptime monitoring
    if path in ("/health", "/api/health", "/robots.txt", "/favicon.ico", MONITORING_ENDPOINT_PATH):
        return True, "EXEMPT_PATH"

    expected_secret = settings.CLOUDFLARE_SECRET_TOKEN.strip()
    incoming_secret = (
        headers.get("x-render-secret") or
        headers.get("x-hrta-edge-secret") or
        headers.get("x-cloudflare-secret") or
        ""
    ).strip()

    # TIER A: Secret token configured & matched
    if expected_secret and incoming_secret:
        if hmac.compare_digest(expected_secret.encode("utf-8"), incoming_secret.encode("utf-8")):
            return True, "TIER_A_TOKEN_VERIFIED"

    # TIER B: Cloudflare headers presence check
    cf_ip = headers.get("cf-connecting-ip")
    cf_ray = headers.get("cf-ray")
    if cf_ip and cf_ray:
        return True, "TIER_B_CF_HEADERS_VERIFIED"

    # TIER C: Direct attack / bypass attempt
    return False, "Direct origin access forbidden: Missing mandatory edge security headers."


def verify_monitoring_authorization(authorization: Optional[str]) -> bool:
    """Verify the dedicated monitoring bearer token without accepting query parameters."""
    expected_secret = settings.MONITORING_ENDPOINT_SECRET
    if not expected_secret or not authorization:
        return False

    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return False

    return hmac.compare_digest(
        expected_secret.encode("utf-8"),
        parts[1].encode("utf-8")
    )


def is_valid_host(host_header: Optional[str]) -> bool:
    """
    Validates Host header against allowed whitelist to prevent HTTP Host Header Poisoning.
    """
    if not host_header:
        return False
    host = host_header.split(":")[0].strip().lower()

    if host in settings.ALLOWED_HOSTS:
        return True

    # Allow official subdomains of hrtacbt.in or temporary render testing domain
    if host.endswith(".hrtacbt.in") or host.endswith(".onrender.com"):
        return True

    return False


def is_valid_origin(origin_header: Optional[str]) -> bool:
    """
    Validates request Origin or Referer against allowed CBT portal domains.
    """
    if not origin_header:
        # Internal API calls without Origin are permitted if Edge Shield passes
        return True

    origin_cleaned = origin_header.strip().lower()
    if origin_cleaned in settings.ALLOWED_ORIGINS:
        return True

    # Regex pattern: https://(*.)hrtacbt.in
    pattern = r"^https:\/\/(.*\.)?hrtacbt\.in$"
    if re.match(pattern, origin_cleaned):
        return True

    return False


def check_rate_limit(client_ip: str) -> bool:
    """
    In-Memory sliding window rate limiter. Returns True if within limit, False if exceeded.
    """
    global _last_cleanup_time
    now = time.time()

    # Periodic cleanup of old keys every 60 seconds
    if now - _last_cleanup_time > 60:
        cutoff = now - 60
        keys_to_delete = []
        for ip, timestamps in _rate_limit_records.items():
            _rate_limit_records[ip] = [t for t in timestamps if t > cutoff]
            if not _rate_limit_records[ip]:
                keys_to_delete.append(ip)
        for k in keys_to_delete:
            del _rate_limit_records[k]
        _last_cleanup_time = now

    timestamps = _rate_limit_records.setdefault(client_ip, [])
    # Keep only timestamps in the last 60 seconds
    cutoff = now - 60
    valid_timestamps = [t for t in timestamps if t > cutoff]
    _rate_limit_records[client_ip] = valid_timestamps

    if len(valid_timestamps) >= settings.MAX_REQUESTS_PER_MINUTE:
        return False

    valid_timestamps.append(now)
    return True


def verify_exam_session_token(token: str, expected_exam_id: str, expected_student_id: str) -> Tuple[bool, str]:
    """
    Cryptographically verifies candidate examSessionToken generated by HRTA CBT Controller.
    Format: {examId}.{studentId}.{timestampMs}.{hmacSha256Hex}
    """
    if not token or not isinstance(token, str):
        return False, "Missing or invalid exam session token header (x-exam-session-token)."

    parts = token.strip().split(".")
    if len(parts) != 4:
        return False, "Malformed exam session token format."

    token_exam_id, token_student_id, timestamp_str, signature = parts

    if token_exam_id != expected_exam_id or token_student_id != expected_student_id:
        return False, "Exam session token does not match the active candidate and exam."

    try:
        timestamp_ms = int(timestamp_str)
    except ValueError:
        return False, "Invalid timestamp in session token."

    now_ms = int(time.time() * 1000)
    # 24-hour validity window with 5 min future clock skew tolerance
    if (now_ms - timestamp_ms) > (24 * 60 * 60 * 1000) or timestamp_ms > (now_ms + 5 * 60 * 1000):
        return False, "Exam session token has expired. Please re-verify login."

    secret = settings.SUPER_ADMIN_SECRET
    if not secret:
        # If secret is unconfigured during initial dev setup, allow with warning
        return True, "DEV_MODE_NO_SECRET"

    expected_sig = hmac.new(
        secret.encode("utf-8"),
        f"{token_exam_id}:{token_student_id}:{timestamp_ms}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature.lower(), expected_sig.lower()):
        return False, "Cryptographic signature forgery detected in exam session token."

    return True, "AUTHENTIC_SESSION"
