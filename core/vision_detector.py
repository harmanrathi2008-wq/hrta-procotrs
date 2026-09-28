import cv2
import numpy as np
import base64
import time
import threading
from typing import Dict, Any, List, Optional
import mediapipe as mp
from .config import settings

# Thread lock for MediaPipe processing (not thread-safe by default in C++ backend)
_vision_lock = threading.Lock()

# Initialize MediaPipe Solutions once globally for high throughput
mp_face_detection = mp.solutions.face_detection
mp_face_mesh = mp.solutions.face_mesh

# Face Detector for presence and multi-face count
face_detector = mp_face_detection.FaceDetection(
    model_selection=0,  # 0 for short-range (< 2 meters webcam)
    min_detection_confidence=0.55
)

# Face Mesh for 3D Head Pose and Gaze tracking
face_mesh = mp_face_mesh.FaceMesh(
    max_num_faces=2,
    refine_landmarks=True,
    min_detection_confidence=0.55,
    min_tracking_confidence=0.55
)

# Standard 3D Facial Model Reference Points (PnP Model)
MODEL_POINTS_3D = np.array([
    (0.0, 0.0, 0.0),          # Nose tip (Landmark 1)
    (0.0, -330.0, -65.0),      # Chin (Landmark 152)
    (-225.0, 170.0, -135.0),   # Left eye outer corner (Landmark 263)
    (225.0, 170.0, -135.0),    # Right eye outer corner (Landmark 33)
    (-150.0, -150.0, -125.0),  # Left mouth corner (Landmark 287)
    (150.0, -150.0, -125.0)    # Right mouth corner (Landmark 57)
], dtype=np.float64)

# In-memory candidate state trackers (StudentId -> Timestamp / Data)
candidate_down_tracker: Dict[str, float] = {}
candidate_missing_face_tracker: Dict[str, float] = {}
candidate_multi_face_tracker: Dict[str, float] = {}
candidate_yaw_tracker: Dict[str, Dict[str, Any]] = {}
candidate_device_tracker: Dict[str, float] = {}

def decode_image_base64(image_str: str) -> Optional[np.ndarray]:
    """Decodes data URI or raw base64 string to OpenCV BGR image"""
    try:
        if "," in image_str:
            image_str = image_str.split(",")[1]
        image_bytes = base64.b64decode(image_str)
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        return img
    except Exception:
        return None

def check_camera_tampering(img: np.ndarray) -> Optional[str]:
    """Detects black screen, covered camera, or extreme darkness"""
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    avg_brightness = np.mean(gray)
    if avg_brightness < 8.0:
        return "CAMERA_BLOCKED_OR_BLACK"
    
    # Check for frozen / zero variance (solid white or blank wall)
    variance = np.var(gray)
    if variance < 5.0:
        return "CAMERA_FEED_BLANK"
    
    return None

def estimate_head_pose(landmarks, img_w: int, img_h: int) -> Dict[str, float]:
    """Calculates 3D Head Pose Euler angles (Yaw, Pitch, Roll) using solvePnP"""
    image_points = np.array([
        (landmarks[1].x * img_w, landmarks[1].y * img_h),      # Nose tip
        (landmarks[152].x * img_w, landmarks[152].y * img_h),  # Chin
        (landmarks[263].x * img_w, landmarks[263].y * img_h),  # Left eye outer
        (landmarks[33].x * img_w, landmarks[33].y * img_h),   # Right eye outer
        (landmarks[287].x * img_w, landmarks[287].y * img_h),  # Left mouth corner
        (landmarks[57].x * img_w, landmarks[57].y * img_h)    # Right mouth corner
    ], dtype=np.float64)

    # Approximate focal length and camera matrix
    focal_length = img_w
    center = (img_w / 2, img_h / 2)
    camera_matrix = np.array([
        [focal_length, 0, center[0]],
        [0, focal_length, center[1]],
        [0, 0, 1]
    ], dtype=np.float64)

    dist_coeffs = np.zeros((4, 1)) # Assume no lens distortion
    success, rot_vec, trans_vec = cv2.solvePnP(
        MODEL_POINTS_3D, image_points, camera_matrix, dist_coeffs, flags=cv2.SOLVEPNP_ITERATIVE
    )

    if not success:
        return {"yaw": 0.0, "pitch": 0.0, "roll": 0.0}

    # Convert rotation vector to Euler angles
    rot_mat, _ = cv2.Rodrigues(rot_vec)
    angles, _, _, _, _, _ = cv2.RQDecomp3x3(rot_mat)

    # angles: [pitch, yaw, roll] in degrees
    pitch = float(angles[0])
    yaw = float(angles[1])
    roll = float(angles[2])

    return {"yaw": round(yaw, 2), "pitch": round(pitch, 2), "roll": round(roll, 2)}

def detect_illuminated_device(img: np.ndarray) -> bool:
    """
    Lightweight heuristic detector for illuminated rectangular devices (mobile phone screens / tablets).
    Filters out flat desk paper and requires smartphone-like geometry at upper body level.
    """
    try:
        hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
        _, _, v = cv2.split(hsv)
        thresh = cv2.adaptiveThreshold(v, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        contours, _ = cv2.findContours(thresh, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        
        img_h, img_w = img.shape[:2]
        img_area = img_h * img_w

        for cnt in contours:
            area = cv2.contourArea(cnt)
            # Filter contours matching a smartphone size in the frame (1.5% to 15% of frame area)
            if 0.015 * img_area < area < 0.15 * img_area:
                perimeter = cv2.arcLength(cnt, True)
                approx = cv2.approxPolyDP(cnt, 0.04 * perimeter, True)
                if len(approx) == 4: # Rectangular geometry
                    x, y, w, h = cv2.boundingRect(approx)
                    # Device held up at chest/head level (not flat at very bottom of desk)
                    if y < 0.85 * img_h:
                        aspect_ratio = float(w) / h
                        # Portrait smartphone (0.45 - 0.65) or landscape (1.5 - 2.2)
                        if (0.42 <= aspect_ratio <= 0.68) or (1.45 <= aspect_ratio <= 2.25):
                            return True
        return False
    except Exception:
        return False

def _cleanup_stale_trackers(now: float):
    cutoff = now - 3600
    for tracker in (candidate_down_tracker, candidate_missing_face_tracker, candidate_multi_face_tracker, candidate_device_tracker):
        if len(tracker) > 500:
            stale = [k for k, v in tracker.items() if v < cutoff]
            for k in stale:
                tracker.pop(k, None)
    if len(candidate_yaw_tracker) > 500:
        stale = [k for k, v in candidate_yaw_tracker.items() if v.get("start", 0) < cutoff]
        for k in stale:
            candidate_yaw_tracker.pop(k, None)

def analyze_proctor_frame(image_str: str, student_id: str, exam_id: str) -> Dict[str, Any]:
    """
    Unified Real-Time Computer Vision Proctoring Pipeline with Temporal Debouncing
    Executes Face Count, 3D Head Pose, Academic Solving Gaze, and Tampering checks
    with strict suppression of transient false positives.
    """
    img = decode_image_base64(image_str)
    if img is None:
        return {
            "status": "ERROR",
            "violation": "CORRUPT_FRAME",
            "message": "Invalid or unreadable image frame received.",
            "penalty": 0,
            "risk_score_increment": 0
        }

    h, w, _ = img.shape
    now = time.time()
    _cleanup_stale_trackers(now)

    # 1. Camera Tampering Check
    tamper_result = check_camera_tampering(img)
    if tamper_result:
        return {
            "status": "VIOLATION",
            "violation": tamper_result,
            "face_count": 0,
            "warning": "Warning: Your webcam feed appears black or covered. Ensure clear lighting.",
            "penalty": 6,
            "risk_score_increment": 6,
            "details": {"reason": "Camera covered or lighting too dark"}
        }

    # Convert to RGB for MediaPipe processing
    rgb_img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

    # 2. Face Presence & Count Detection (Thread-safe inference)
    with _vision_lock:
        detection_results = face_detector.process(rgb_img)
        raw_faces = detection_results.detections if detection_results else []
        
        # Filter faces by minimum confidence (0.60) to eliminate background noise/shadows
        valid_faces = []
        for det in raw_faces:
            score = det.score[0] if det.score else 0.5
            if score >= 0.60:
                valid_faces.append(det)
        
        face_count = len(valid_faces)
        mesh_results = None
        if face_count == 1:
            mesh_results = face_mesh.process(rgb_img)

    # --- Case A: Face Undetected (Debounced with 3.5s Grace Period) ---
    if face_count == 0:
        candidate_down_tracker.pop(student_id, None)
        candidate_yaw_tracker.pop(student_id, None)
        candidate_multi_face_tracker.pop(student_id, None)
        
        first_missing_time = candidate_missing_face_tracker.get(student_id)
        if not first_missing_time:
            candidate_missing_face_tracker[student_id] = now
            return {
                "status": "CLEAR",
                "face_count": 0,
                "mode": "TEMPORARY_OCCLUSION_GRACE",
                "warning": None,
                "penalty": 0,
                "risk_score_increment": 0,
                "note": "Face briefly obscured. Grace period active."
            }

        missing_duration = now - first_missing_time
        if missing_duration < 3.5:
            # Within 3.5 second grace period (normal blink, scratch, momentary head turn)
            return {
                "status": "CLEAR",
                "face_count": 0,
                "mode": "TEMPORARY_OCCLUSION_GRACE",
                "warning": None,
                "penalty": 0,
                "risk_score_increment": 0,
                "note": f"Face obscured ({round(missing_duration, 1)}s/3.5s). Suppressing warning."
            }
        else:
            # Sustained absence confirmed
            return {
                "status": "VIOLATION",
                "violation": "NO_FACE_DETECTED",
                "face_count": 0,
                "warning": "Warning: Face not detected. Please position yourself directly in front of the camera.",
                "penalty": 6,
                "risk_score_increment": 6,
                "details": {"duration_missing_seconds": round(missing_duration, 1)}
            }
    else:
        # Face is visible — reset missing face tracker
        candidate_missing_face_tracker.pop(student_id, None)

    # --- Case B: Multiple Faces Detected (Debounced with 2.0s Persistence) ---
    if face_count > 1:
        candidate_down_tracker.pop(student_id, None)
        candidate_yaw_tracker.pop(student_id, None)
        
        first_multi_time = candidate_multi_face_tracker.get(student_id)
        if not first_multi_time:
            candidate_multi_face_tracker[student_id] = now
            return {
                "status": "CLEAR",
                "mode": "VERIFYING_MULTI_FACE",
                "face_count": face_count,
                "warning": None,
                "penalty": 0,
                "risk_score_increment": 0,
                "note": "Transient secondary face detected. Verifying persistence."
            }

        multi_duration = now - first_multi_time
        if multi_duration < 2.0:
            return {
                "status": "CLEAR",
                "mode": "VERIFYING_MULTI_FACE",
                "face_count": face_count,
                "warning": None,
                "penalty": 0,
                "risk_score_increment": 0
            }
        else:
            # Sustained second person confirmed
            return {
                "status": "VIOLATION",
                "violation": "MULTIPLE_FACES_DETECTED",
                "face_count": face_count,
                "warning": "Critical Alert: Multiple faces detected in your examination area!",
                "penalty": 12,
                "risk_score_increment": 12,
                "details": {"faces": face_count, "sustained_seconds": round(multi_duration, 1)}
            }
    else:
        candidate_multi_face_tracker.pop(student_id, None)

    # --- Case C: 1 Face Detected — Head Pose & Academic Gaze Tracking ---
    head_pose = {"yaw": 0.0, "pitch": 0.0, "roll": 0.0}
    if mesh_results and mesh_results.multi_face_landmarks:
        landmarks = mesh_results.multi_face_landmarks[0].landmark
        head_pose = estimate_head_pose(landmarks, w, h)

    yaw = head_pose["yaw"]
    pitch = head_pose["pitch"]

    # 3. Gaze Deviation: Looking Away (Yaw > 38°) with 3.5s Temporal Persistence
    is_looking_left_right = abs(yaw) > settings.YAW_LOOK_AWAY_THRESHOLD_DEG
    if is_looking_left_right:
        direction = "RIGHT" if yaw > 0 else "LEFT"
        candidate_down_tracker.pop(student_id, None)
        
        yaw_record = candidate_yaw_tracker.get(student_id)
        if not yaw_record or yaw_record.get("direction") != direction:
            candidate_yaw_tracker[student_id] = {"start": now, "direction": direction}
            return {
                "status": "CLEAR",
                "mode": "GAZE_GRACE",
                "face_count": 1,
                "head_pose": head_pose,
                "penalty": 0,
                "risk_score_increment": 0,
                "note": f"Glancing {direction.lower()}. Temporal smoothing active."
            }

        yaw_duration = now - yaw_record["start"]
        if yaw_duration < 3.5:
            # Allowed momentary glances at timer / question palette / screen corners
            return {
                "status": "CLEAR",
                "mode": "GAZE_GRACE",
                "face_count": 1,
                "head_pose": head_pose,
                "penalty": 0,
                "risk_score_increment": 0
            }
        else:
            # Sustained head turn away from monitor
            return {
                "status": "VIOLATION",
                "violation": f"LOOKING_AWAY_{direction}",
                "face_count": 1,
                "head_pose": head_pose,
                "warning": f"Notice: Please focus your eyes on the exam screen. Looking away ({direction.lower()}) detected.",
                "penalty": 3,
                "risk_score_increment": 3,
                "details": {**head_pose, "sustained_seconds": round(yaw_duration, 1)}
            }
    else:
        candidate_yaw_tracker.pop(student_id, None)

    # 4. Academic Solving / Rough Work Intelligence (Pitch > 20°)
    is_looking_down = pitch > settings.PITCH_DOWN_THRESHOLD_DEG
    if is_looking_down:
        first_down_time = candidate_down_tracker.get(student_id)
        if not first_down_time:
            candidate_down_tracker[student_id] = now
            first_down_time = now

        duration_down_sec = now - first_down_time
        # Generous rough work window: up to ROUGH_WORK_TOLERANCE_SECONDS (75s default)
        if duration_down_sec <= settings.ROUGH_WORK_TOLERANCE_SECONDS:
            return {
                "status": "CLEAR",
                "mode": "SOLVING_ON_PAPER",
                "face_count": 1,
                "head_pose": head_pose,
                "warning": None,
                "penalty": 0,
                "risk_score_increment": 0,
                "note": f"Candidate active in rough work solving ({round(duration_down_sec, 1)}s elapsed)."
            }
        else:
            # Soft notice after prolonged head-down without looking up
            return {
                "status": "NOTICE",
                "violation": "SUSPICIOUS_PROLONGED_HEAD_DOWN",
                "face_count": 1,
                "head_pose": head_pose,
                "warning": "Reminder: Please look up at the exam interface periodically while solving.",
                "penalty": 1,
                "risk_score_increment": 1,
                "details": {"duration_down_seconds": round(duration_down_sec, 1)}
            }
    else:
        candidate_down_tracker.pop(student_id, None)

    # 5. Mobile Phone Screen & Gadget Detection (Debounced with 2.5s Persistence)
    device_found = detect_illuminated_device(img)
    if device_found:
        first_device_time = candidate_device_tracker.get(student_id)
        if not first_device_time:
            candidate_device_tracker[student_id] = now
            return {
                "status": "CLEAR",
                "mode": "VERIFYING_OBJECT",
                "face_count": 1,
                "head_pose": head_pose,
                "penalty": 0,
                "risk_score_increment": 0
            }

        device_duration = now - first_device_time
        if device_duration >= 2.5:
            return {
                "status": "VIOLATION",
                "violation": "CELL_PHONE_OR_DEVICE_DETECTED",
                "face_count": 1,
                "head_pose": head_pose,
                "warning": "Critical Security Warning: Prohibited electronic device or phone detected!",
                "penalty": 15,
                "risk_score_increment": 15,
                "details": {"object": "electronic_device", "sustained_seconds": round(device_duration, 1)}
            }
    else:
        candidate_device_tracker.pop(student_id, None)

    # All Clear: High Integrity Nominal Exam Condition
    return {
        "status": "CLEAR",
        "face_count": 1,
        "head_pose": head_pose,
        "warning": None,
        "penalty": 0,
        "risk_score_increment": 0
    }
