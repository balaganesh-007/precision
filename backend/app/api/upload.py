import os
import shutil
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models import Model
from backend.app.schemas import UploadResponse, ModelOut
from backend.app.config import settings
from backend.app.utils.file_helper import compute_sha256, detect_format, is_allowed_file

router = APIRouter(prefix="/models", tags=["models"])

@router.post("/upload", response_model=UploadResponse)
def upload_model(file: UploadFile = File(...), db: Session = Depends(get_db)):
    # 1. Validate file extension
    if not is_allowed_file(file.filename):
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported file format. Supported: .onnx, .safetensors, .pt, .pth, .bin"
        )
    
    # 2. Save file to temporary path to compute hash
    temp_path = os.path.join(settings.UPLOAD_DIR, f"temp_{file.filename}")
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Compute SHA256
        sha256_hash = compute_sha256(temp_path)
        
        # 3. Check database for existing model (Deduplication)
        existing_model = db.query(Model).filter(Model.sha256_hash == sha256_hash).first()
        if existing_model:
            # Delete temp file as we already have this model stored
            os.remove(temp_path)
            return {
                "model": existing_model,
                "message": "Model already uploaded and indexed. Reusing existing entry."
            }
            
        # 4. Save new model
        filename = file.filename
        file_size = os.path.getsize(temp_path)
        format_detected = detect_format(filename)
        
        final_filename = f"{sha256_hash}_{filename}"
        final_path = os.path.join(settings.UPLOAD_DIR, final_filename)
        
        # Rename temp file to final location
        shutil.move(temp_path, final_path)
        
        # Register in database
        db_model = Model(
            name=filename,
            format=format_detected,
            file_size=file_size,
            sha256_hash=sha256_hash
        )
        db.add(db_model)
        db.commit()
        db.refresh(db_model)
        
        return {
            "model": db_model,
            "message": "Model uploaded successfully."
        }
        
    except Exception as e:
        # Clean up temp file on failure
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=500, detail=f"File upload processing failed: {str(e)}")
