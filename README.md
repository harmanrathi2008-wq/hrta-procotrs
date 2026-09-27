# HRTA Real-Time Cloud AI Proctoring Engine 🛡️

Official Real-Time Computer Vision and Biometric Telemetry Microservice for Harman Rathi Testing Agency (HRTA CBT Portal).

## Core Capabilities
- **Face Presence & Multi-Person Guard**: Instant detection of absent candidate (`NO_FACE`) or unauthorized helpers (`MULTIPLE_FACES_DETECTED`).
- **3D Head Pose & Gaze Tracking**: MediaPipe 468-point 3D Face Mesh tracking horizontal and vertical Euler angles (Yaw/Pitch).
- **Academic Rough Work Solving Intelligence**: Automatically recognizes when candidates look down at rough paper to solve mathematical formulas without triggering false positives (configurable tolerance window).
- **Electronic Device & Cell Phone Detector**: Edge-contour illumination and aspect-ratio detection for unauthorized mobile devices.
- **Camera Tampering Defense**: Instant flag for covered camera, blank frames, or low-light obscurity.
- **Authoritative Risk Sync**: Directly logs timestamped violation evidence to Supabase `proctoring_events` and auto-increments candidate AI risk scores.

## Architecture & Integration
- **Host Domain**: `https://proctor.hrtacbt.in`
- **Main Portal**: `https://hrtacbt.in`
- **Central API**: `https://api.hrtacbt.in`
- **Database**: Supabase PostgreSQL

## Quick Local Run
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Production Deployment (Render)
1. Link GitHub repository to Render Web Service.
2. Select **Docker** environment.
3. Configure Environment Variables:
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `SUPER_ADMIN_SECRET`
   - `MAIN_API_URL`
4. Set Cloudflare CNAME `proctor` -> `<your-render-subdomain>.onrender.com`.
