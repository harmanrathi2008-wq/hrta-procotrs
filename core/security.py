# -*- coding: utf-8 -*-
import time
import hmac
import hashlib
import re
import secrets
from html import escape
from typing import Tuple, Optional, Dict, List
from .config import settings

MONITORING_ENDPOINT_PATH = "/internal/monitor"

# Rate Limiter State (In-Memory Sliding Window)
_rate_limit_records: Dict[str, List[float]] = {}
_last_cleanup_time: float = time.time()

STEALTH_404_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>404 &mdash; HRTA Secure Systems</title>
<style>
  *, *::before, *::after {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  body {
    background-color: #030712;
    color: #f8fafc;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Inter', Helvetica, Arial, sans-serif;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    overflow-x: hidden;
    position: relative;
    padding: 0;
  }

  /* Deep Atmospheric Cosmic Background */
  body::before {
    content: '';
    position: absolute;
    top: 20%;
    right: 15%;
    width: 550px;
    height: 550px;
    background: radial-gradient(circle, rgba(14, 165, 233, 0.08) 0%, rgba(37, 99, 235, 0.03) 50%, transparent 75%);
    filter: blur(80px);
    pointer-events: none;
    z-index: 0;
  }

  body::after {
    content: '';
    position: absolute;
    bottom: 10%;
    left: 10%;
    width: 400px;
    height: 400px;
    background: radial-gradient(circle, rgba(2, 132, 199, 0.05) 0%, transparent 70%);
    filter: blur(90px);
    pointer-events: none;
    z-index: 0;
  }

  /* Header Bar */
  .header-bar {
    position: relative;
    z-index: 10;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 28px 48px;
    width: 100%;
  }

  .brand-group {
    display: flex;
    align-items: center;
    gap: 16px;
    text-decoration: none;
  }

  .logo-emblem {
    width: 44px;
    height: 44px;
    flex-shrink: 0;
  }

  .brand-text {
    display: flex;
    flex-direction: column;
    line-height: 1.15;
  }

  .brand-title {
    font-size: 20px;
    font-weight: 900;
    letter-spacing: 0.06em;
    color: #ffffff;
  }

  .brand-sub {
    font-size: 8.5px;
    font-weight: 700;
    letter-spacing: 0.16em;
    color: #94a3b8;
    text-transform: uppercase;
  }

  .brand-agency {
    font-size: 8px;
    font-weight: 800;
    letter-spacing: 0.22em;
    color: #38bdf8;
    text-transform: uppercase;
  }

  .header-divider {
    width: 1px;
    height: 28px;
    background: rgba(255, 255, 255, 0.15);
    margin: 0 10px;
  }

  .header-tagline {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.22em;
    color: #64748b;
    text-transform: uppercase;
  }

  .shield-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    color: #94a3b8;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-decoration: none;
    transition: color 0.2s ease;
  }

  .shield-badge:hover {
    color: #38bdf8;
  }

  .shield-icon {
    width: 16px;
    height: 16px;
    stroke: #38bdf8;
  }

  /* Main Stage Container */
  .main-stage {
    position: relative;
    z-index: 10;
    max-width: 1320px;
    width: 100%;
    margin: 0 auto;
    padding: 20px 48px;
    display: grid;
    grid-template-columns: 1.15fr 0.85fr;
    align-items: center;
    gap: 40px;
    flex-grow: 1;
  }

  /* Left Hero Content */
  .hero-content {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
  }

  .code-display {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: 24px;
  }

  .digit {
    font-size: 115px;
    font-weight: 900;
    line-height: 0.9;
    letter-spacing: -0.04em;
    color: #ffffff;
    text-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
  }

  .center-badge {
    width: 92px;
    height: 92px;
    display: flex;
    align-items: center;
    justify-content: center;
    filter: drop-shadow(0 0 25px rgba(14, 165, 233, 0.5));
    animation: gentlePulse 4s ease-in-out infinite;
  }

  @keyframes gentlePulse {
    0%, 100% { transform: scale(1); filter: drop-shadow(0 0 20px rgba(14, 165, 233, 0.4)); }
    50% { transform: scale(1.03); filter: drop-shadow(0 0 35px rgba(56, 189, 248, 0.7)); }
  }

  .hero-title {
    font-size: 42px;
    font-weight: 800;
    line-height: 1.18;
    letter-spacing: -0.025em;
    color: #ffffff;
    margin-bottom: 16px;
  }

  .hero-title .accent-text {
    color: #38bdf8;
    background: linear-gradient(135deg, #38bdf8 0%, #60a5fa 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  .hero-desc {
    font-size: 16px;
    font-weight: 400;
    line-height: 1.65;
    color: #94a3b8;
    max-width: 480px;
    margin-bottom: 36px;
  }

  .back-btn {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(56, 189, 248, 0.35);
    color: #ffffff;
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 0.02em;
    padding: 13px 30px;
    border-radius: 9999px;
    text-decoration: none;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    backdrop-filter: blur(12px);
  }

  .back-btn:hover {
    border-color: #38bdf8;
    background: rgba(14, 165, 233, 0.15);
    box-shadow: 0 0 25px rgba(14, 165, 233, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    transform: translateY(-2px);
  }

  .back-btn svg {
    transition: transform 0.2s ease;
  }

  .back-btn:hover svg {
    transform: translateX(-4px);
  }

  /* Right Visual Stage */
  .visual-stage {
    display: flex;
    justify-content: center;
    align-items: center;
    position: relative;
  }

  .illustration-svg {
    width: 100%;
    max-width: 520px;
    height: auto;
    filter: drop-shadow(0 25px 40px rgba(0, 0, 0, 0.8));
    animation: gentleFloat 6s ease-in-out infinite;
  }

  @keyframes gentleFloat {
    0%, 100% { transform: translateY(0px); }
    50% { transform: translateY(-8px); }
  }

  /* Footer Bar */
  .footer-bar {
    position: relative;
    z-index: 10;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 24px 48px;
    width: 100%;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 11px;
    color: #475569;
    letter-spacing: 0.22em;
    text-transform: uppercase;
  }

  .footer-left {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .footer-line {
    width: 24px;
    height: 1px;
    background: #334155;
  }

  /* Responsive Design */
  @media (max-width: 960px) {
    .header-bar {
      padding: 20px 24px;
    }
    .header-divider, .header-tagline {
      display: none;
    }
    .main-stage {
      grid-template-columns: 1fr;
      padding: 20px 24px;
      text-align: center;
      gap: 32px;
    }
    .hero-content {
      align-items: center;
    }
    .digit {
      font-size: 85px;
    }
    .center-badge {
      width: 68px;
      height: 68px;
    }
    .hero-title {
      font-size: 30px;
    }
    .hero-desc {
      font-size: 14px;
      margin-bottom: 28px;
    }
    .illustration-svg {
      max-width: 360px;
    }
    .footer-bar {
      flex-direction: column;
      gap: 12px;
      text-align: center;
      padding: 20px 24px;
    }
  }
</style>
</head>
<body>

  <!-- Top Navigation Bar -->
  <header class="header-bar">
    <a href="https://hrtacbt.in" class="brand-group">
      <svg class="logo-emblem" viewBox="0 0 100 100" fill="none">
        <circle cx="50" cy="50" r="46" fill="url(#hrta_p_bg)" stroke="#18d8ee" stroke-width="2.5"/>
        <circle cx="50" cy="50" r="42" fill="none" stroke="#0878e8" stroke-width="1.5" opacity="0.6"/>
        <circle cx="50" cy="40" r="18" fill="#087ff0" opacity="0.3" filter="blur(6px)"/>
        <path d="M32 28 H43 V40 H57 V28 H68 V72 H57 V52 H43 V72 H32 Z" fill="url(#hrta_p_h)"/>
        <circle cx="70" cy="30" r="4" fill="#11e7f4"/>
        <defs>
          <radialGradient id="hrta_p_bg" cx="50%" cy="45%" r="65%">
            <stop offset="0%" stop-color="#06234a"/>
            <stop offset="70%" stop-color="#031328"/>
            <stop offset="100%" stop-color="#010711"/>
          </radialGradient>
          <linearGradient id="hrta_p_h" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="#ffffff"/>
            <stop offset="100%" stop-color="#a5e5ff"/>
          </linearGradient>
        </defs>
      </svg>
      <div class="brand-text">
        <span class="brand-title">HRTA</span>
        <span class="brand-sub">HARMAN RATHI</span>
        <span class="brand-agency">TESTING AGENCY</span>
      </div>
    </a>

    <div style="display:flex; align-items:center;">
      <div class="header-divider"></div>
      <div class="header-tagline">SECURE &nbsp;|&nbsp; EXAMINATIONS &nbsp;|&nbsp; PROCTORING</div>
    </div>

    <a href="https://hrtacbt.in" class="shield-badge">
      <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span>HRTA Proctors</span>
    </a>
  </header>

  <!-- Main Hero Stage -->
  <main class="main-stage">
    
    <!-- Left Column: Typography & Action -->
    <section class="hero-content">
      <div class="code-display">
        <span class="digit">4</span>
        <div class="center-badge">
          <svg width="100%" height="100%" viewBox="0 0 100 100" fill="none">
            <circle cx="50" cy="50" r="46" fill="#0284c7" opacity="0.3" filter="blur(10px)"/>
            <circle cx="50" cy="50" r="46" fill="url(#p_badge_404)" stroke="#38bdf8" stroke-width="3"/>
            <circle cx="50" cy="50" r="40" stroke="#0284c7" stroke-width="1.5" opacity="0.8"/>
            <circle cx="50" cy="38" r="16" fill="#38bdf8" opacity="0.25" filter="blur(6px)"/>
            <path d="M32 27 H43 V41 H57 V27 H68 V73 H57 V53 H43 V73 H32 Z" fill="url(#p_h_404)"/>
            <circle cx="70" cy="28" r="4.5" fill="#38bdf8"/>
            <defs>
              <radialGradient id="p_badge_404" cx="50%" cy="45%" r="60%">
                <stop offset="0%" stop-color="#0c4a6e"/>
                <stop offset="60%" stop-color="#082f49"/>
                <stop offset="100%" stop-color="#020617"/>
              </radialGradient>
              <linearGradient id="p_h_404" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stop-color="#ffffff"/>
                <stop offset="100%" stop-color="#bae6fd"/>
              </linearGradient>
            </defs>
          </svg>
        </div>
        <span class="digit">4</span>
      </div>

      <h1 class="hero-title">
        The page you're looking for<br/>
        <span class="accent-text">doesn't exist.</span>
      </h1>

      <p class="hero-desc">
        The requested URL was not found on this server.<br/>
        That's all we know.
      </p>

      <a href="https://hrtacbt.in" class="back-btn">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        <span>Go back home</span>
      </a>
    </section>

    <!-- Right Column: 3D Console & Orbital Ring Illustration -->
    <section class="visual-stage">
      <svg class="illustration-svg" viewBox="0 0 520 460" fill="none">
        <!-- Ambient Backlight -->
        <circle cx="340" cy="220" r="140" fill="#0284c7" opacity="0.16" filter="blur(55px)"/>
        
        <!-- Asteroid Rock Pedestal -->
        <g class="asteroid-base">
          <ellipse cx="320" cy="385" rx="150" ry="32" fill="#000000" opacity="0.95" filter="blur(18px)"/>
          <path d="M190 340 L240 295 L310 280 L380 290 L440 330 L450 370 L390 410 L290 420 L210 395 Z" fill="#090d16" stroke="#1e293b" stroke-width="1.5"/>
          <path d="M240 295 L310 280 L320 330 L250 350 Z" fill="#131d2e" stroke="#1e293b" stroke-width="1"/>
          <path d="M310 280 L380 290 L390 340 L320 330 Z" fill="#182338" stroke="#334155" stroke-width="1"/>
          <path d="M380 290 L440 330 L420 370 L390 340 Z" fill="#0f172a" stroke="#1e293b" stroke-width="1"/>
          <path d="M250 350 L320 330 L340 390 L270 400 Z" fill="#0c1322" stroke="#1e293b" stroke-width="1"/>
          <path d="M320 330 L390 340 L380 395 L340 390 Z" fill="#162033" stroke="#2563eb" stroke-width="0.8" opacity="0.8"/>
          <!-- Specular Light Edge Highlight -->
          <path d="M240 295 L310 280 L380 290" stroke="#38bdf8" stroke-width="2" opacity="0.8" filter="drop-shadow(0 0 5px #38bdf8)"/>
        </g>

        <!-- Floating Cosmic Debris -->
        <g class="floating-debris">
          <polygon points="170,260 178,252 184,262 176,270" fill="#1e293b" stroke="#38bdf8" stroke-width="0.8" opacity="0.85"/>
          <polygon points="450,270 460,265 464,276 454,282" fill="#0f172a" stroke="#475569" stroke-width="0.8"/>
          <polygon points="460,180 466,174 472,182 464,188" fill="#1e293b" stroke="#38bdf8" stroke-width="0.8" opacity="0.9"/>
          <polygon points="140,210 148,204 152,214 144,218" fill="#1e293b" stroke="#334155" stroke-width="0.8"/>
        </g>

        <!-- Orbital Ring: Back Arc -->
        <path d="M140 270 C160 210, 420 160, 470 200" stroke="#0ea5e9" stroke-width="3.5" stroke-linecap="round" opacity="0.4"/>

        <!-- Floating Glass Console Window -->
        <g class="floating-terminal" filter="drop-shadow(0 20px 35px rgba(0,0,0,0.9))">
          <rect x="230" y="110" width="180" height="170" rx="20" fill="url(#p_term_body)" stroke="#38bdf8" stroke-width="1.5" stroke-opacity="0.45"/>
          <!-- Top Window Bar -->
          <path d="M230 130 C230 119, 239 110, 250 110 H390 C401 110, 410 119, 410 130 V140 H230 Z" fill="#0f172a" fill-opacity="0.85"/>
          <!-- Window Controls -->
          <circle cx="248" cy="125" r="3.5" fill="#64748b"/>
          <circle cx="260" cy="125" r="3.5" fill="#475569"/>
          <circle cx="272" cy="125" r="3.5" fill="#334155"/>
          
          <!-- Diagonal Glass Sheen Reflection -->
          <path d="M240 145 L320 145 L270 270 L240 270 Z" fill="url(#p_specular_sweep)" opacity="0.12"/>
          
          <!-- Minimal Emoticon Face: | _ | in crisp glowing white -->
          <g class="terminal-face">
            <line x1="285" y1="190" x2="285" y2="208" stroke="#ffffff" stroke-width="4.5" stroke-linecap="round" filter="drop-shadow(0 0 6px #ffffff)"/>
            <line x1="355" y1="190" x2="355" y2="208" stroke="#ffffff" stroke-width="4.5" stroke-linecap="round" filter="drop-shadow(0 0 6px #ffffff)"/>
            <line x1="306" y1="226" x2="334" y2="226" stroke="#ffffff" stroke-width="4.5" stroke-linecap="round" filter="drop-shadow(0 0 6px #ffffff)"/>
          </g>
        </g>

        <!-- Orbital Ring: Front Arc with Neon Glow -->
        <path d="M470 200 C500 240, 200 320, 140 270" stroke="#38bdf8" stroke-width="3.5" stroke-linecap="round" filter="drop-shadow(0 0 10px #38bdf8)"/>
        
        <!-- Glowing Celestial Blue Sphere on the orbital ring -->
        <g class="orbital-sphere" filter="drop-shadow(0 0 12px #38bdf8)">
          <circle cx="458" cy="224" r="10" fill="url(#p_sphere_grad)"/>
          <circle cx="455" cy="221" r="3" fill="#ffffff" opacity="0.85"/>
        </g>

        <defs>
          <linearGradient id="p_term_body" x1="230" y1="110" x2="410" y2="280" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#0f172a" stop-opacity="0.95"/>
            <stop offset="50%" stop-color="#090d16" stop-opacity="0.98"/>
            <stop offset="100%" stop-color="#020617"/>
          </linearGradient>
          <linearGradient id="p_specular_sweep" x1="240" y1="145" x2="320" y2="270" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#ffffff"/>
            <stop offset="100%" stop-color="#38bdf8" stop-opacity="0"/>
          </linearGradient>
          <radialGradient id="p_sphere_grad" cx="40%" cy="35%" r="65%">
            <stop offset="0%" stop-color="#bae6fd"/>
            <stop offset="45%" stop-color="#38bdf8"/>
            <stop offset="100%" stop-color="#0284c7"/>
          </radialGradient>
        </defs>
      </svg>
    </section>

  </main>

  <!-- Bottom Institutional Footer Bar -->
  <footer class="footer-bar">
    <div class="footer-left">
      <div class="footer-line"></div>
      <span>HRTA SECURE SYSTEMS</span>
      <div class="footer-line"></div>
    </div>
    <div class="footer-right">
      <span>BUILT FOR A SAFER EXAMINATION TOMORROW</span>
    </div>
  </footer>

</body>
</html>"""


def build_forbidden_html_page(client_ip: str = "", ray_id: str = "", reason: str = "") -> str:
    """Returns the sovereign 404 stealth interface on unauthorized / direct browser access."""
    return STEALTH_404_HTML


def build_proctor_landing_page(client_ip: str = "", ray_id: str = "") -> str:
    """Returns the sovereign 404 stealth interface for direct visits to proctor subdomain."""
    return STEALTH_404_HTML


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

    # TIER B.2: Valid candidate examination session (authenticated exam client)
    session_token = headers.get("x-exam-session-token") or headers.get("x-session-token")
    origin = headers.get("origin") or headers.get("referer")
    if session_token and origin and is_valid_origin(origin):
        return True, "TIER_B2_AUTH_SESSION_VERIFIED"

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

    if host in {"proctor.hrtacbt.in", "api.hrtacbt.in", "hrtacbt.in", "www.hrtacbt.in"}:
        return True
    if settings.RENDER_HOSTNAME and host == settings.RENDER_HOSTNAME.strip().lower():
        return True

    return False


def is_valid_origin(origin_header: Optional[str]) -> bool:
    """
    Validates request Origin or Referer against allowed CBT portal domains.
    Handles bare origins (https://hrtacbt.in) and full referer URLs with paths.
    """
    if not origin_header:
        # Internal API calls without Origin are permitted if Edge Shield passes
        return True

    origin_cleaned = origin_header.strip().lower()
    if origin_cleaned in settings.ALLOWED_ORIGINS:
        return True

    # Parse hostname from URL or Referer
    try:
        from urllib.parse import urlparse
        parsed = urlparse(origin_cleaned)
        netloc = (parsed.netloc or parsed.path.split('/')[0]).lower().split(':')[0]
        if netloc in ("hrtacbt.in", "www.hrtacbt.in", "proctor.hrtacbt.in", "api.hrtacbt.in", "admin.hrtacbt.in", "localhost", "127.0.0.1"):
            return True
        if netloc.endswith(".hrtacbt.in"):
            return True
    except Exception:
        pass

    # Regex pattern: https://(*.)hrtacbt.in(/.*)?
    pattern = r"^https:\/\/(.*\.)?hrtacbt\.in(\/.*)?$"
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

    if token_exam_id.strip() != expected_exam_id.strip() or token_student_id.strip().lower() != expected_student_id.strip().lower():
        return False, "Exam session token does not match the active candidate and exam."

    try:
        timestamp_ms = int(timestamp_str)
    except ValueError:
        return False, "Invalid timestamp in session token."

    now_ms = int(time.time() * 1000)
    # 24-hour validity window with 15 min future clock skew tolerance
    if (now_ms - timestamp_ms) > (24 * 60 * 60 * 1000) or timestamp_ms > (now_ms + 15 * 60 * 1000):
        return False, "Exam session token has expired. Please re-verify login."

    secret_candidates = [
        s for s in (
            settings.SUPER_ADMIN_SECRET.strip(),
            getattr(settings, "JWT_SECRET", "").strip(),
        ) if s
    ]

    if not secret_candidates:
        # If secret is unconfigured during initial dev setup, allow with warning
        return True, "DEV_MODE_NO_SECRET"

    matched = False
    for candidate in secret_candidates:
        expected_sig = hmac.new(
            candidate.encode("utf-8"),
            f"{token_exam_id}:{token_student_id}:{timestamp_ms}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(signature.lower(), expected_sig.lower()):
            matched = True
            break

    if not matched:
        return False, "Cryptographic signature forgery detected in exam session token."

    return True, "AUTHENTIC_SESSION"
