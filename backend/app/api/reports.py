import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models import Report, Scan

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/{scan_id}/download")
def download_scan_report(scan_id: int, db: Session = Depends(get_db)):
    # 1. Check scan completion
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
        
    if scan.status != "COMPLETED":
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot download report for a scan with status '{scan.status}'."
        )
        
    # 2. Retrieve report
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if not report or not report.report_path or not os.path.exists(report.report_path):
        raise HTTPException(status_code=404, detail="Report file not generated or missing on disk.")
        
    # Get model name for custom filename
    model_name = scan.model.name if scan.model else "model"
    report_filename = f"Security_Report_{model_name}_{scan_id}.md"
    
    return FileResponse(
        path=report.report_path, 
        filename=report_filename, 
        media_type="text/markdown"
    )
