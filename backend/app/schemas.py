from pydantic import BaseModel, Field
from typing import List, Optional, Any
from datetime import datetime

# Finding Schemas
class FindingBase(BaseModel):
    severity: str
    module: str
    title: str
    description: str
    layer_name: Optional[str] = None
    evidence: Optional[Any] = None

class FindingCreate(FindingBase):
    pass

class FindingOut(FindingBase):
    id: int
    scan_id: int
    created_at: datetime

    class Config:
        from_attributes = True

# Model Schemas
class ModelBase(BaseModel):
    name: str
    format: str
    file_size: int
    sha256_hash: str

class ModelCreate(ModelBase):
    pass

class ModelOut(ModelBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

# Report Schemas
class ReportOut(BaseModel):
    id: int
    scan_id: int
    report_path: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

# Scan Schemas
class ScanBase(BaseModel):
    model_id: int

class ScanCreate(ScanBase):
    pass

class ScanOut(BaseModel):
    id: int
    model_id: int
    status: str
    risk_score: Optional[int] = None
    risk_classification: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True

class ScanHistoryOut(ScanOut):
    model: ModelOut

    class Config:
        from_attributes = True

class ScanDetailOut(ScanOut):
    model: ModelOut
    findings: List[FindingOut] = []
    reports: List[ReportOut] = []

    class Config:
        from_attributes = True

# File upload response schema
class UploadResponse(BaseModel):
    model: ModelOut
    message: str
