import os
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_api_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "database_type" in data

def test_get_scan_history():
    response = client.get("/api/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_upload_and_scan_pipeline():
    # 1. Upload clean_model.onnx
    clean_model_path = os.path.join("test_models", "clean_model.onnx")
    assert os.path.exists(clean_model_path)
    
    with open(clean_model_path, "rb") as f:
        response = client.post(
            "/api/models/upload",
            files={"file": ("clean_model.onnx", f, "application/octet-stream")}
        )
    
    assert response.status_code == 200
    data = response.json()
    assert "model" in data
    assert data["model"]["name"] == "clean_model.onnx"
    assert data["model"]["format"] == "ONNX"
    
    model_id = data["model"]["id"]
    
    # 2. Trigger Scan
    scan_response = client.post(
        "/api/scans/start",
        json={"model_id": model_id}
    )
    assert scan_response.status_code == 200
    scan_data = scan_response.json()
    assert scan_data["model_id"] == model_id
    assert scan_data["status"] in {"PENDING", "RUNNING", "COMPLETED"}
