import uvicorn
import os
import sys

# Ensure the parent directory is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == "__main__":
    print("Starting AI Model Security Scanner Backend...")
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
