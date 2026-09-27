import time
import datetime
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from core.config import settings
from core.security import verify_exam_session_token
from core.vision_detector import analyze_proctor_frame
from core.db_sync import record_proctoring_violation

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Real-Time Cloud AI Proctoring & Computer Vision Telemetry Engine for HRTA CBT"
)

# Configure CORS for Official Portal & Localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

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
def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "ONLINE_ACTIVE",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "academic_solving_mode": "ACTIVE (30s tolerance on rough work desk gaze)"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "time": time.time(),
        "uptime": "operational"
    }

@app.post("/api/v1/proctor/inspect")
async def inspect_proctor_frame(
    payload: FrameInspectRequest,
    request: Request,
    x_exam_session_token: Optional[str] = Header(None, alias="x-exam-session-token"),
    x_student_id: Optional[str] = Header(None, alias="x-student-id")
):
    """
    Primary Real-Time Visual Inspection Endpoint
    Analyzes face presence, 3D head pose, rough work solving, and electronic devices.
    """
    resolved_student_id = payload.studentId or x_student_id
    if not resolved_student_id or not payload.examId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="studentId and examId are mandatory."
        )

    # 1. Cryptographic Session Token Verification
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
    client_ip = request.headers.get("cf-connecting-ip") or request.headers.get("x-forwarded-for") or request.client.host
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
    Real-Time Audio & Whispering Inspection Endpoint
    """
    if not payload.studentId or not payload.examId:
        raise HTTPException(status_code=400, detail="studentId and examId required.")

    client_ip = request.headers.get("cf-connecting-ip") or request.client.host

    if payload.speechDetected or payload.decibels > 68.0:
        db_res = await record_proctoring_violation(
            student_id=payload.studentId,
            exam_id=payload.examId,
            violation_type="SPEECH_OR_NOISE_DETECTED",
            penalty_increment=5,
            details={
                "decibels": payload.decibels,
                "speechDetected": payload.speechDetected
            },
            client_ip=client_ip
        )
        return {
            "success": True,
            "status": "VIOLATION",
            "violation": "SPEECH_OR_NOISE_DETECTED",
            "warning": "Warning: High volume background talking or speech detected!",
            "penalty": 5,
            "riskScore": db_res.get("new_risk_score", 5)
        }

    return {
        "success": True,
        "status": "CLEAR",
        "decibels": payload.decibels
    }
