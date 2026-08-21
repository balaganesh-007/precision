import hashlib
import os

ALLOWED_EXTENSIONS = {'.onnx', '.safetensors', '.pt', '.pth', '.bin'}

def compute_sha256(filepath: str) -> str:
    """Compute the SHA256 checksum of a file in chunks."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def detect_format(filename: str) -> str:
    """Detect the model format based on the file extension."""
    ext = os.path.splitext(filename.lower())[1]
    if ext == '.onnx':
        return 'ONNX'
    elif ext == '.safetensors':
        return 'SAFETENSORS'
    elif ext in {'.pt', '.pth', '.bin'}:
        return 'PYTORCH'
    return 'UNKNOWN'

def is_allowed_file(filename: str) -> bool:
    """Check if the file extension is supported."""
    ext = os.path.splitext(filename.lower())[1]
    return ext in ALLOWED_EXTENSIONS
