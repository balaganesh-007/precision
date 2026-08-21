import datetime
from sqlalchemy import Column, Integer, String, BigInteger, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base

class Model(Base):
    __tablename__ = "models"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    format = Column(String(50), nullable=False)  # ONNX, SAFETENSORS, PYTORCH
    file_size = Column(BigInteger, nullable=False)
    sha256_hash = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    scans = relationship("Scan", back_populates="model", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(Integer, ForeignKey("models.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(50), default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED
    risk_score = Column(Integer, nullable=True)  # 0 to 100
    risk_classification = Column(String(50), nullable=True)  # CLEAN, SUSPICIOUS, HIGH_RISK
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    model = relationship("Model", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    severity = Column(String(50), nullable=False)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    module = Column(String(100), nullable=False)  # FORMAT, WEIGHTS, STEGO, BEHAVIOR
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    layer_name = Column(String(255), nullable=True)
    evidence = Column(JSON, nullable=True)  # Detailed stats or raw indicators
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    report_path = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="reports")
