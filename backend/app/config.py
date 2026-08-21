import os
from dotenv import load_dotenv

# Load environmental variables from .env file
load_dotenv()

class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "mysql+pymysql://scanner_user:scanner_password_2026@localhost:3306/model_security_scanner"
    )
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")
    ENV: str = os.getenv("ENV", "development")

settings = Settings()

# Ensure uploads folder exists
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
