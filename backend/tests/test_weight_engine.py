import os
from backend.app.modules.weight_engine import WeightEngine
from backend.app.modules.stego_detector import StegoDetector
from backend.app.modules.behavior_analyzer import BehaviorAnalyzer

def test_clean_model_passes_all_static_scans():
    clean_model_path = os.path.join("test_models", "clean_model.onnx")
    assert os.path.exists(clean_model_path)

    # 1. Weight Engine Scan
    engine = WeightEngine()
    findings = engine.scan(clean_model_path, "ONNX")
    assert len(findings) == 0, f"Clean model should have 0 weight anomalies, got: {findings}"

    # 2. Stego Scan
    stego_det = StegoDetector()
    stego_findings = stego_det.scan(clean_model_path, "ONNX")
    # Low warnings might exist if entropy falls in boundaries, but CRITICAL stego markers should be 0
    critical_stego = [f for f in stego_findings if f["severity"] == "CRITICAL"]
    assert len(critical_stego) == 0

    # 3. Behavior Graph Scan
    behavior_det = BehaviorAnalyzer()
    behavior_findings = behavior_det.scan(clean_model_path, "ONNX")
    assert len(behavior_findings) == 0


def test_anomalous_model_fails_weight_scans():
    anomalous_path = os.path.join("test_models", "anomalous_model.onnx")
    assert os.path.exists(anomalous_path)

    engine = WeightEngine()
    findings = engine.scan(anomalous_path, "ONNX")
    
    # Expecting: NaN values, Inf values, and extreme outliers
    assert len(findings) >= 3
    
    titles = [f["title"] for f in findings]
    assert any("NaN" in t for t in titles)
    assert any("Infinite" in t for t in titles)
    assert any("Outlier" in t for t in titles)


def test_stego_model_fails_stego_scans():
    stego_path = os.path.join("test_models", "stego_model.onnx")
    assert os.path.exists(stego_path)

    stego_det = StegoDetector()
    findings = stego_det.scan(stego_path, "ONNX")
    
    assert len(findings) > 0
    critical_findings = [f for f in findings if f["severity"] == "CRITICAL"]
    assert len(critical_findings) == 1
    assert "Hidden Payload Marker Detected" in critical_findings[0]["title"]
    assert critical_findings[0]["evidence"]["marker_found"] == "STEGO_DEMO_MARKER_2026"
