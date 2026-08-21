from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from typing import List
from backend.app.database import get_db
from backend.app.models import Model, Scan
from backend.app.schemas import ScanOut, ScanDetailOut, ScanHistoryOut
from backend.app.core.orchestrator import run_model_scan

router = APIRouter(prefix="/scans", tags=["scans"])

class ScanRequest(ScanOut.__config__.schema_extra if hasattr(ScanOut, '__config__') else object):
    # Standard request body
    pass

from pydantic import BaseModel
class StartScanRequest(BaseModel):
    model_id: int

@router.post("/start", response_model=ScanOut)
def start_scan(request: StartScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 1. Verify model exists
    model = db.query(Model).filter(Model.id == request.model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model file record not found.")
        
    # 2. Create scan entry
    scan = Scan(
        model_id=request.model_id,
        status="PENDING"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # 3. Add to background executor task
    background_tasks.add_task(run_model_scan, db, scan.id)
    
    return scan

@router.get("", response_model=List[ScanHistoryOut])
def get_scan_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    scans = db.query(Scan).order_by(Scan.started_at.desc()).offset(skip).limit(limit).all()
    return scans

@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return scan
