import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "HRTA Cloud Proctoring Engine"
    APP_VERSION: str = "1.0.0"
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Database and Central Controller
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_SERVICE_ROLE_KEY: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    SUPER_ADMIN_SECRET: str = os.getenv("SUPER_ADMIN_SECRET", "")
    MAIN_API_URL: str = os.getenv("MAIN_API_URL", "https://api.hrtacbt.in")
    
    # Exam Solving Tolerances (Academic JEE / NEET Solving Settings)
    ROUGH_WORK_TOLERANCE_SECONDS: int = int(os.getenv("ROUGH_WORK_TOLERANCE_SECONDS", "30"))
    PITCH_DOWN_THRESHOLD_DEG: float = 12.0  # Angle threshold for looking down at rough paper
    YAW_LOOK_AWAY_THRESHOLD_DEG: float = 28.0  # Angle threshold for looking left/right
    
    # Allowed CORS Origins
    ALLOWED_ORIGINS: list = [
        "https://hrtacbt.in",
        "https://www.hrtacbt.in",
        "https://api.hrtacbt.in",
        "https://proctor.hrtacbt.in",
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173"
    ]

settings = Settings()
