# Aegis: AI Model Security Scanner MVP

Aegis is a defensive AI model security scanner designed to detect suspicious content, hidden payloads, structural anomalies, and potential code-injection or backdoor indicators in machine-learning model artifacts.

The project was developed for the **Precision Care Challenge 2026** challenge:

> Detection of Steganographic Malware Hidden in AI Model Weights

Aegis combines static model inspection, steganography-aware analysis, pickle security scanning, ONNX graph analysis, controlled behavioral probing, and an explainable risk engine.

---

## Security Scope

Aegis is designed as a defensive analysis tool.

### Static analysis

Model files are inspected without executing arbitrary code or deserializing untrusted pickle objects.

For PyTorch-style files, Aegis analyzes pickle instructions using Python's `pickletools` module instead of loading the model with unsafe deserialization.

### Controlled behavioral analysis

For supported ONNX models, Aegis can perform a controlled inference probe using ONNX Runtime.

The behavioral probe uses deterministic test inputs and checks the resulting outputs for anomalies such as:

- NaN values
- Infinite values
- non-finite outputs

This is a controlled security test and **does not prove that a model contains or does not contain a backdoor**.

---

# Features

## 1. Model Intake

Aegis accepts and analyzes multiple model artifact formats, including:

- `.onnx`
- `.safetensors`
- `.pt`
- `.pth`
- `.bin`

Supported analysis depends on the model format and available metadata.

---

## 2. Static Pickle Opcode Scanner

PyTorch-style model containers can contain Python pickle instructions.

Instead of executing the pickle payload, Aegis extracts and inspects pickle instructions using `pickletools`.

The scanner looks for suspicious references involving potentially dangerous modules and builtins, including examples such as:

- `os`
- `sys`
- `subprocess`
- `eval`
- `exec`
- `print`

This provides a defensive way to identify suspicious pickle structures without executing the potentially unsafe code.

### Example finding

```text
Suspicious Pickle Import Detected
Module: builtins.print
Opcode: STACK_GLOBAL