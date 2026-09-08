# Aegis: AI Model Security Scanner MVP

A defensive, static-analysis cybersecurity tool designed to audit machine learning models for hidden payloads, structural anomalies, and code injection vulnerabilities.

**This tool operates strictly in read-only/static mode. It never executes arbitrary code, runs malicious payloads, or modifies the uploaded model files.**

---

## Technical Features

1. **Static Pickle Opcode Scanner**: Intercepts PyTorch `.pt`/`.pth`/`.bin` zip containers and decodes pickle instructions statically using Python's `pickletools`. It intercepts imports of risky packages (`os`, `sys`, `subprocess`) or builtins (`eval`, `exec`, `print`) to prevent Remote Code Execution (RCE) vulnerabilities.

2. **Model Analysis Engine**: Statically reads weight tensors (ONNX and Safetensors) and runs statistical calculations to flag infinite values, NaNs, and extreme range outliers (e.g. weight magnitudes > 10^6).

3. **Steganography Detector**: Extracts float32 mantissa bits, computes the Shannon entropy of the Least Significant Bits (LSBs) to locate non-natural uniform randomness patterns, and checks LSB byte streams for file headers (PE, ELF, ZIP) or target demonstration markers.

4. **Controlled Graph Analyzer**: Inspects ONNX graph nodes statically for unregistered custom operator definitions and detects potential backdoor indicators by checking for highly skewed bias layers.

5. **Explainable Risk Engine**: Aggregates finding weights to output a final threat score with transparent justifications and human-readable findings.

---

## Tech Stack

- **Backend**: Python (FastAPI, SQLAlchemy, NumPy, ONNX, Safetensors, PyMySQL)

- **Frontend**: React + TypeScript (Vite, custom Cyber dark/glassmorphic CSS layout)

- **Database**: MySQL (with automatic local SQLite fallback `scanner.db` if MySQL is unavailable)

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