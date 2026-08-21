# Aegis: AI Model Security Scanner MVP

A defensive, static-analysis cybersecurity tool designed to audit machine learning models for hidden payloads, structural anomalies, and code injection vulnerabilities. 

**This tool operates strictly in read-only/static mode. It never executes arbitrary code, runs malicious payloads, or modifies the uploaded model files.**

---

## Technical Features

1. **Static Pickle Opcode Scanner**: Intercepts PyTorch `.pt`/`.pth`/`.bin` zip containers and decodes pickle instructions statically using Python's `pickletools`. It intercepts imports of risky packages (`os`, `sys`, `subprocess`) or builtins (`eval`, `exec`, `print`) to prevent Remote Code Execution (RCE) vulnerabilities.
2. **Model Analysis Engine**: Statically reads weight tensors (ONNX and Safetensors) and runs statistical calculations to flag infinite values, NaNs, and extreme range outliers (e.g. weight magnitudes > 10^6).
3. **Steganography Detector**: Extracts float32 mantissa bits, computes the Shannon entropy of the Least Significant Bits (LSBs) to locate non-natural uniform randomness patterns, and checks LSB byte streams for file headers (PE, ELF, ZIP) or target demonstration markers.
4. **Controlled Graph Analyzer**: Inspects ONNX graph nodes statically for unregistered custom operator definitions and detects potential backdoor triggers (Trojans) by checking for highly skewed bias layers.
5. **Explainable Risk Engine**: Aggregates finding weights to output a final threat score from `0–99` (never claims 100% certainty) with transparent justifications.

---

## Tech Stack

- **Backend**: Python (FastAPI, SQLAlchemy, NumPy, ONNX, Safetensors, PyMySQL)
- **Frontend**: React + TypeScript (Vite, custom Cyber dark/glassmorphic CSS layout)
- **Database**: MySQL (with automatic local SQLite fallback `scanner.db` if MySQL is down)

---

## Setup & Running Instructions

### Prerequisites
- Python 3.10+
- Node.js 18+
- MySQL (Optional, Docker setup provided. Fallback to SQLite is automatic)

### 1. Database Setup (Optional)
If Docker is installed, start MySQL:
```bash
docker compose up -d
```
Otherwise, the application will automatically initialize a local SQLite file named `scanner.db` on launch.

### 2. Backend Setup
1. Open a terminal in the root workspace.
2. The virtual environment is located under `backend/venv/`. Install dependencies:
   ```bash
   backend/venv/Scripts/pip install -r backend/requirements.txt
   ```
3. Generate the safe demonstration models:
   ```bash
   backend/venv/Scripts/python test_models/generate_test_models.py
   ```
4. Start the FastAPI development server:
   ```bash
   backend/venv/Scripts/python backend/run.py
   ```
   The backend API will run at `http://localhost:8000`.

### 3. Frontend Setup
1. Open a new terminal in the `frontend/` directory.
2. Install Node packages:
   ```bash
   npm install
   ```
3. Start the Vite React development server:
   ```bash
   npm run dev
   ```
   Open the browser at `http://localhost:5173`.

---

## Running Backend Tests

The backend includes a comprehensive unit and integration test suite to verify all static analysis engines.
Run the test suite:
```bash
backend/venv/Scripts/python -m pytest backend/tests/
```

---

## Verification Walkthrough (Demo)

On the dashboard UI, you can test the scanner by uploading any of the pre-generated test targets from `test_models/`:

1. **`clean_model.onnx`**: A normal feed-forward network. Scan returns **CLEAN** (Score: `0`).
2. **`stego_model.onnx`**: Embeds a safe text string in the LSBs. Scan flags **HIGH RISK** (Score: `90+`) and extracts the text marker.
3. **`anomalous_model.onnx`**: Contains NaNs and extreme outlier numbers. Scan flags **SUSPICIOUS / HIGH RISK** (Score: `50+`) and lists the affected layers.
4. **`unsafe_pickle.pth`**: Simulates a PyTorch file containing a builtin function call. Scan flags **HIGH RISK** (Score: `90+`) and points to the exact opcode position.
