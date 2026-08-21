import logging
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from backend.app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("database")

db_url = settings.DATABASE_URL
engine = None
SessionLocal = None

# Attempt to connect to MySQL database
try:
    if db_url.startswith("mysql"):
        logger.info("Attempting to connect to MySQL database...")
        # Add a short timeout to fail fast if MySQL is down
        connect_args = {"connect_timeout": 3}
        engine = create_engine(db_url, connect_args=connect_args)
        # Verify connection
        with engine.connect() as conn:
            logger.info("Successfully connected to MySQL database!")
except Exception as e:
    logger.warning(
        f"MySQL connection failed: {e}. "
        "Falling back to local SQLite database 'scanner.db' for development/demo."
    )
    db_url = "sqlite:///./scanner.db"

# Setup SQLite fallback or secondary setup
if engine is None or db_url.startswith("sqlite"):
    db_url = "sqlite:///./scanner.db"
    engine = create_engine(
        db_url, 
        connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {}
    )
    logger.info("SQLite database engine initialized.")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
