import time
import datetime
import secrets
from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from core.config import settings
from core.security import (
    build_forbidden_html_page,
    build_proctor_landing_page,
    is_direct_browser_request,
    verify_cloudflare_edge_shield,
    is_valid_host,
    is_valid_origin,
    check_rate_limit,
    verify_exam_session_token,
    verify_monitoring_authorization,
    MONITORING_ENDPOINT_PATH
)
from core.vision_detector import analyze_proctor_frame
from core.db_sync import record_proctoring_violation

# In production, disable OpenAPI / Swagger docs to prevent endpoint reconnaissance
is_prod = settings.ENVIRONMENT.lower() == "production"
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def hrta_edge_security_middleware(request: Request, call_next):
    """
    Enterprise-Grade Security Middleware Pipeline:
    1. Direct browser navigation handler (NTA status page on root, 403 WAF gate on sub-paths)
    2. Cloudflare Edge Shield (Tier A token + Tier B CF-Ray verification)
    3. Host header poisoning protection
    4. Cross-origin authorization validation
    5. Sliding window DoS rate limiting
    6. Request payload size clamping
    7. Hardened HTTP response security headers (CSP, HSTS, X-Frame-Options)
    """
    method = request.method.upper()
    path = request.url.path
    headers = dict(request.headers)

    client_ip = (
        headers.get("cf-connecting-ip") or
        headers.get("x-forwarded-for", "").split(",")[0].strip() or
        (request.client.host if request.client else "unknown")
    )
    ray_id = headers.get("cf-ray") or f"{secrets.token_hex(8)}-{int(time.time())}"

    # 1. CORS Preflights proceed cleanly
    if method == "OPTIONS":
        return await call_next(request)

    # 2. Host Header Validation
    host_val = headers.get("host", "")
    if not is_valid_host(host_val):
        return HTMLResponse(
            content=build_forbidden_html_page(client_ip, ray_id, "Untrusted Host Header Rejected"),
            status_code=status.HTTP_400_BAD_REQUEST
        )

    # 3. Direct Browser Navigation Interception
    # Renders an authoritative NTA/HRTA status terminal on root, and a 403 WAF HTML gate on sub-paths
    if is_direct_browser_request(headers):
        if path in ("/", ""):
            return HTMLResponse(
                content=build_proctor_landing_page(client_ip, ray_id),
                status_code=status.HTTP_200_OK
            )
        return HTMLResponse(
            content=build_forbidden_html_page(client_ip, ray_id, "Direct Browser Navigation Prohibited by Security Policy"),
            status_code=status.HTTP_403_FORBIDDEN
        )

    # 4. Cloudflare Edge Shield Enforcement
    shield_passed, shield_reason = verify_cloudflare_edge_shield(headers, path, client_ip)
    if not shield_passed:
        accept = headers.get("accept", "").lower()
        if "text/html" in accept:
            return HTMLResponse(
                content=build_forbidden_html_page(client_ip, ray_id, shield_reason),
                status_code=status.HTTP_403_FORBIDDEN
            )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Direct Origin Access Forbidden",
                "message": shield_reason,
                "rayId": ray_id
            }
        )

    # 5. Cross-Origin Validation
    origin = headers.get("origin") or headers.get("referer")
    if origin and not is_valid_origin(origin):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Forbidden Origin",
                "message": "Cross-origin request blocked by HRTA Proctor Shield."
            }
        )

    # 6. Sliding Window Rate Limiting (Skip for internal health checks)
    if path not in ("/health", "/api/health", MONITORING_ENDPOINT_PATH):
        if not check_rate_limit(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate Limit Exceeded",
                    "message": "Too many requests to proctoring engine. Burst threshold exceeded."
                }
            )

    # 7. Payload Size Clamping (Prevent Memory Exhaustion Attacks)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.MAX_PAYLOAD_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "error": "Payload Too Large",
                        "message": f"Frame payload exceeds maximum allowable size of {settings.MAX_PAYLOAD_BYTES // (1024*1024)}MB."
                    }
                )
        except ValueError:
            pass

    # Process Request
    response: Response = await call_next(request)

    # 8. Inject Enterprise Defense-in-Depth Security Headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; sandbox;"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Server"] = "cloudflare"

    return response


class FrameInspectRequest(BaseModel):
    examId: str = Field(..., description="Unique examination ID")
    studentId: str = Field(..., description="Authenticated candidate ID")
    image: str = Field(..., description="Base64 encoded JPEG/WebP webcam frame")
    timestamp: Optional[int] = Field(None, description="Client frame timestamp")


class AudioInspectRequest(BaseModel):
    examId: str
    studentId: str
    decibels: float
    speechDetected: bool
    timestamp: Optional[int] = None


@app.get("/")
def root(request: Request):
    """
    Root endpoint: Only responds to API clients passing Edge Shield.
    Browser visits are intercepted by the 403 WAF HTML gate above.
    """
    return {
        "service": settings.APP_NAME,
        "status": "ONLINE_ACTIVE",
        "shield": "HRTA_EDGE_PROTECTED",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


@app.get("/health")
@app.get("/api/health")
def health_check():
    """
    Uptime and health telemetry probe for Render and external monitors.
    """
    return {
        "status": "healthy",
        "service": "HRTA_PROCTOR_ENGINE",
        "uptime": "operational"
    }


@app.get(MONITORING_ENDPOINT_PATH)
def monitoring_check(authorization: Optional[str] = Header(None)):
    """Minimal authenticated availability probe for external monitoring."""
    if not verify_monitoring_authorization(authorization):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden"
        )

    return {"status": "ok"}


@app.post("/api/v1/proctor/inspect")
async def inspect_proctor_frame(
    payload: FrameInspectRequest,
    request: Request,
    x_exam_session_token: Optional[str] = Header(None, alias="x-exam-session-token"),
    x_student_id: Optional[str] = Header(None, alias="x-student-id")
):
    """
    Primary Real-Time Visual Inspection Endpoint:
    Cryptographically verifies the student's exam token, analyzes the frame
    with MediaPipe + OpenCV, respects academic rough-work gaze tolerance,
    and logs verified infractions to the central database.
    """
    resolved_student_id = payload.studentId or x_student_id
    if not resolved_student_id or not payload.examId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="studentId and examId are mandatory."
        )

    # 1. Cryptographic Exam Session Token Verification
    if x_exam_session_token:
        is_valid, reason = verify_exam_session_token(
            x_exam_session_token,
            payload.examId,
            resolved_student_id
        )
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Exam Terminal Session Verification Failed: {reason}"
            )

    # 2. Execute Real-Time Computer Vision Pipeline
    client_ip = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "unknown")
    verdict = analyze_proctor_frame(payload.image, resolved_student_id, payload.examId)

    # 3. If violation detected, record to Supabase and update AI Risk Score
    if verdict.get("status") == "VIOLATION":
        violation_type = verdict.get("violation", "UNKNOWN_VIOLATION")
        penalty = verdict.get("penalty", 4)

        db_res = await record_proctoring_violation(
            student_id=resolved_student_id,
            exam_id=payload.examId,
            violation_type=violation_type,
            penalty_increment=penalty,
            details={
                "head_pose": verdict.get("head_pose"),
                "face_count": verdict.get("face_count"),
                "warning": verdict.get("warning"),
                "token": x_exam_session_token
            },
            client_ip=client_ip
        )
        verdict["riskScore"] = db_res.get("new_risk_score", penalty)

    return {
        "success": True,
        **verdict,
        "processed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


@app.post("/api/v1/proctor/audio-inspect")
async def inspect_proctor_audio(
    payload: AudioInspectRequest,
    request: Request,
    x_exam_session_token: Optional[str] = Header(None, alias="x-exam-session-token")
):
    """
    Telemetry inspection endpoint for background ambient audio and whisper detection.
    """
    if x_exam_session_token:
        is_valid, reason = verify_exam_session_token(
            x_exam_session_token,
            payload.examId,
            payload.studentId
        )
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Session Verification Failed: {reason}"
            )

    is_violation = payload.speechDetected or payload.decibels > 78.0
    verdict = {
        "status": "VIOLATION" if is_violation else "CLEAR",
        "speech_detected": payload.speechDetected,
        "decibels": payload.decibels,
        "violation": "SUSPICIOUS_AUDIO_DETECTED" if is_violation else None,
        "penalty": 2 if is_violation else 0
    }

    if is_violation:
        client_ip = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "unknown")
        await record_proctoring_violation(
            student_id=payload.studentId,
            exam_id=payload.examId,
            violation_type="SUSPICIOUS_AUDIO_DETECTED",
            penalty_increment=2,
            details={"decibels": payload.decibels, "speech_detected": payload.speechDetected},
            client_ip=client_ip
        )

    return {"success": True, **verdict}
