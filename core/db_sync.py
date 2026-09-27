import datetime
from typing import Dict, Any, Optional
from supabase import create_client, Client
import httpx
from .config import settings

# Initialize Supabase client if credentials are present
supabase: Optional[Client] = None
if settings.SUPABASE_URL and settings.SUPABASE_SERVICE_ROLE_KEY:
    try:
        supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
    except Exception as e:
        print(f"[Supabase Init Error]: {e}")

async def record_proctoring_violation(
    student_id: str,
    exam_id: str,
    violation_type: str,
    penalty_increment: int,
    details: Dict[str, Any],
    client_ip: str = "Unknown"
) -> Dict[str, Any]:
    """
    Persists proctoring violation into Supabase proctoring_events
    and increments the candidate's authoritative AI Risk Score on exam_results.
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    severity = "critical" if penalty_increment >= 15 else "high" if penalty_increment >= 8 else "medium"

    result_data = {
        "logged_to_db": False,
        "new_risk_score": 0
    }

    if not supabase:
        print(f"[Offline DB Mode] Violation recorded locally: {violation_type} for student {student_id}")
        return result_data

    # 1. Insert into proctoring_events table
    try:
        supabase.table("proctoring_events").insert([{
            "student_id": student_id,
            "exam_id": exam_id,
            "event_type": violation_type,
            "severity": severity,
            "confidence": 0.92,
            "duration_seconds": 1,
            "technical_or_behavioral": "behavioral",
            "metadata": {
                **details,
                "client_ip": client_ip,
                "source": "HRTA_CLOUD_PROCTOR_ENGINE"
            },
            "occurred_at": timestamp
        }]).execute()
        result_data["logged_to_db"] = True
    except Exception as e:
        print(f"[Proctor DB Event Insert Warning]: {e}")

    # 2. Increment AI Risk Score on active exam_results
    try:
        active_results = supabase.table("exam_results") \
            .select("id, marks_adjustments") \
            .eq("student_id", student_id) \
            .eq("exam_id", exam_id) \
            .in_("status", ["in_progress", "submitted", "reviewed"]) \
            .order("created_at", desc=True) \
            .limit(1) \
            .execute()

        if active_results.data and len(active_results.data) > 0:
            current = active_results.data[0]
            adjustments = current.get("marks_adjustments") or {}
            prev_score = adjustments.get("ai_risk_score", 0)
            if not isinstance(prev_score, (int, float)):
                prev_score = 0

            new_score = min(100, int(prev_score + penalty_increment))

            supabase.table("exam_results").update({
                "marks_adjustments": {
                    **adjustments,
                    "ai_risk_score": new_score,
                    "last_violation": violation_type,
                    "last_violation_at": timestamp
                }
            }).eq("id", current["id"]).execute()

            result_data["new_risk_score"] = new_score
    except Exception as e:
        print(f"[Proctor DB Risk Score Increment Warning]: {e}")

    # 3. Notify Central Controller if configured
    if settings.MAIN_API_URL:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(
                    f"{settings.MAIN_API_URL}/api/proctoring/events",
                    json={
                        "exam_id": exam_id,
                        "eventType": violation_type,
                        "confidence": 0.92,
                        "payload": details,
                        "technical_or_behavioral": "behavioral"
                    },
                    headers={"x-exam-session-token": details.get("token", "")}
                )
        except Exception:
            pass  # Non-fatal notification

    return result_data
