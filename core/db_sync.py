import datetime
from typing import Dict, Any, Optional

try:
    from supabase import create_client
except ImportError:
    create_client = None  # type: ignore

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

from .config import settings

# Initialize Supabase client if credentials are present
supabase_client: Any = None
if create_client and settings.SUPABASE_URL and settings.SUPABASE_SERVICE_ROLE_KEY:
    try:
        supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
    except Exception as e:
        print(f"[Supabase Init Error]: {e}")


async def record_proctoring_violation(
    student_id: str,
    exam_id: str,
    violation_type: str,
    penalty_increment: int,
    details: Optional[Dict[str, Any]] = None,
    client_ip: str = "Unknown",
    session_token: str = ""
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

    if not supabase_client:
        print(f"[Offline DB Mode] Violation recorded locally: {violation_type} for student {student_id}")
        return result_data

    # Safely construct metadata dictionary without syntax ambiguity or unpacking issues
    meta_dict: Dict[str, Any] = {}
    if details and isinstance(details, dict):
        for k, v in details.items():
            meta_dict[str(k)] = v
    meta_dict["client_ip"] = str(client_ip)
    meta_dict["source"] = "HRTA_CLOUD_PROCTOR_ENGINE"

    # 1. Insert into proctoring_events table
    try:
        event_record = {
            "student_id": str(student_id),
            "exam_id": str(exam_id),
            "event_type": str(violation_type),
            "severity": str(severity),
            "confidence": 0.92,
            "duration_seconds": 1,
            "technical_or_behavioral": "behavioral",
            "metadata": meta_dict,
            "occurred_at": timestamp
        }
        supabase_client.table("proctoring_events").insert([event_record]).execute()
        result_data["logged_to_db"] = True
    except Exception as e:
        print(f"[Proctor DB Event Insert Warning]: {e}")

    # 2. Increment AI Risk Score on active exam_results
    try:
        query = supabase_client.table("exam_results")
        active_results = query.select("id, marks_adjustments") \
            .eq("student_id", str(student_id)) \
            .eq("exam_id", str(exam_id)) \
            .in_("status", ["in_progress", "submitted", "reviewed"]) \
            .order("created_at", desc=True) \
            .limit(1) \
            .execute()

        if active_results.data and len(active_results.data) > 0:
            current = active_results.data[0]
            raw_adjustments = current.get("marks_adjustments")
            adjustments = dict(raw_adjustments) if isinstance(raw_adjustments, dict) else {}
            
            prev_score = adjustments.get("ai_risk_score", 0)
            if not isinstance(prev_score, (int, float)):
                prev_score = 0

            new_score = min(100, int(prev_score + penalty_increment))

            # Merge cleanly without dictionary unpacking syntax
            merged_adjustments = dict(adjustments)
            merged_adjustments["ai_risk_score"] = new_score
            merged_adjustments["last_violation"] = str(violation_type)
            merged_adjustments["last_violation_at"] = timestamp

            update_payload = {
                "marks_adjustments": merged_adjustments
            }
            supabase_client.table("exam_results").update(update_payload).eq("id", current["id"]).execute()
            result_data["new_risk_score"] = new_score
    except Exception as e:
        print(f"[Proctor DB Risk Score Increment Warning]: {e}")

    # 3. Notify Central Controller if configured
    if settings.MAIN_API_URL and httpx:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                headers = {"x-exam-session-token": session_token} if session_token else {}
                await client.post(
                    f"{settings.MAIN_API_URL}/api/proctoring/events",
                    json={
                        "exam_id": str(exam_id),
                        "eventType": str(violation_type),
                        "confidence": 0.92,
                        "payload": meta_dict,
                        "technical_or_behavioral": "behavioral"
                    },
                    headers=headers
                )
        except Exception:
            pass  # Non-fatal notification

    return result_data
