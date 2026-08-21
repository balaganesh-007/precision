import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.database import Base, engine
from backend.app.api import upload, scans, reports

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("main")

# Auto-create tables (for SQLite fallback or first-run MySQL schema)
try:
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialized successfully.")
except Exception as e:
    logger.error(f"Error initializing database tables: {e}")

app = FastAPI(
    title="AI Model Security Scanner API",
    description="A defensive static analysis API to audit machine learning models for security threats, stego payload injections, and bias anomalies.",
    version="1.0.0"
)

# Enable CORS for frontend API calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for local MVP access
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(upload.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(reports.router, prefix="/api")

@app.get("/api/health")
def health_check():
    """Verify application health and database connection type."""
    from backend.app.database import db_url
    db_type = "MySQL" if db_url.startswith("mysql") else "SQLite"
    return {
        "status": "healthy",
        "database_type": db_type,
        "api_version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
