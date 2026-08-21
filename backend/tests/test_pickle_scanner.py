import os
from backend.app.utils.pickle_scanner import scan_pytorch_pickle

def test_static_pickle_scanner_detects_unsafe_operations():
    # Path to safe simulated test file
    test_file = os.path.join("test_models", "unsafe_pickle.pth")
    assert os.path.exists(test_file), "Test fixture unsafe_pickle.pth is missing."
    
    # Run scan
    findings = scan_pytorch_pickle(test_file)
    
    # Assert findings are captured
    assert len(findings) > 0, "No findings detected in unsafe pickle test model."
    
    # Verify exact details of static interception
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert "builtins.print" in finding["description"]
    assert finding["evidence"]["module"] == "builtins"
    assert finding["evidence"]["name"] == "print"
