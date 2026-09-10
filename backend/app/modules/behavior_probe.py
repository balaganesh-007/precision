import os
from typing import Any, Dict, List

import numpy as np
import onnxruntime as ort


class BehaviorProbe:
    """
    Safe behavioral probe for ONNX models.

    This module performs controlled inference tests against ONNX models.
    It does NOT load or execute PyTorch/Pickle files.
    """

    def __init__(self):
        self.probe_values = {
            "zeros": 0.0,
            "ones": 1.0,
            "positive": 0.1,
            "negative": -0.1,
        }

    def _build_probe_input(self, shape, value):
        """
        Create a deterministic float32 input tensor.

        Fixed integer dimensions are supported.
        Dynamic dimensions are replaced with 1 for this MVP.
        """

        resolved_shape = []

        for dimension in shape:
            if isinstance(dimension, int) and dimension > 0:
                resolved_shape.append(dimension)
            else:
                resolved_shape.append(1)

        return np.full(
            resolved_shape,
            value,
            dtype=np.float32
        )

    def scan(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Run controlled behavioral probes against an ONNX model.
        """

        findings = []

        if not os.path.exists(filepath):
            findings.append({
                "severity": "INFO",
                "title": "Behavioral Analysis Skipped",
                "description": (
                    f"Model file was not found: {filepath}"
                ),
                "layer": None,
                "evidence": {
                    "reason": "file_not_found"
                }
            })
            return findings

        if not filepath.lower().endswith(".onnx"):
            findings.append({
                "severity": "INFO",
                "title": "Behavioral Analysis Skipped",
                "description": (
                    "Behavioral probing is currently limited "
                    "to ONNX models to avoid executing arbitrary "
                    "PyTorch/Pickle model code."
                ),
                "layer": None,
                "evidence": {
                    "format": os.path.splitext(filepath)[1]
                }
            })
            return findings

        try:
            session = ort.InferenceSession(
                filepath,
                providers=["CPUExecutionProvider"]
            )

            input_meta = session.get_inputs()[0]
            input_name = input_meta.name
            input_shape = input_meta.shape

            probe_results = {}

            for probe_name, value in self.probe_values.items():
                probe_input = self._build_probe_input(
                    input_shape,
                    value
                )

                outputs = session.run(
                    None,
                    {
                        input_name: probe_input
                    }
                )

                output = np.asarray(outputs[0])

                probe_results[probe_name] = {
                    "shape": list(output.shape),
                    "mean": float(np.mean(output))
                    if np.all(np.isfinite(output))
                    else None,
                    "std": float(np.std(output))
                    if np.all(np.isfinite(output))
                    else None,
                    "min": float(np.min(output))
                    if np.all(np.isfinite(output))
                    else None,
                    "max": float(np.max(output))
                    if np.all(np.isfinite(output))
                    else None,
                    "has_nan": bool(np.isnan(output).any()),
                    "has_inf": bool(np.isinf(output).any()),
                }

                # Non-finite outputs are a strong behavioral anomaly.
                if np.isnan(output).any() or np.isinf(output).any():
                    findings.append({
                        "severity": "HIGH",
                        "title": "Potential Behavioral Anomaly Detected",
                        "description": (
                            "Controlled inference produced NaN or "
                            "infinite output values. This indicates "
                            "unstable or abnormal model behavior and "
                            "requires further investigation."
                        ),
                        "layer": input_name,
                        "evidence": {
                            "probe": probe_name,
                            "has_nan": bool(np.isnan(output).any()),
                            "has_inf": bool(np.isinf(output).any()),
                        }
                    })

                    # One finding is sufficient for this condition.
                    break

            # Check for unusually large finite outputs.
            if not findings:
                max_abs_output = 0.0

                for result in probe_results.values():
                    if result["max"] is not None:
                        max_abs_output = max(
                            max_abs_output,
                            abs(result["max"])
                        )

                    if result["min"] is not None:
                        max_abs_output = max(
                            max_abs_output,
                            abs(result["min"])
                        )

                if max_abs_output > 1e6:
                    findings.append({
                        "severity": "HIGH",
                        "title": "Potential Behavioral Anomaly Detected",
                        "description": (
                            "Controlled inference produced unusually "
                            "large output values, indicating possible "
                            "numerical instability or abnormal model "
                            "behavior."
                        ),
                        "layer": input_name,
                        "evidence": {
                            "max_abs_output": max_abs_output
                        }
                    })

            if not findings:
                findings.append({
                    "severity": "INFO",
                    "title": "Behavioral Probe Passed",
                    "description": (
                        "Controlled ONNX inference completed with "
                        "finite output values across the probe inputs."
                    ),
                    "layer": input_name,
                    "evidence": {
                        "probes_tested": list(
                            self.probe_values.keys()
                        ),
                        "results": probe_results
                    }
                })

        except Exception as exc:
            findings.append({
                "severity": "MEDIUM",
                "title": "Behavioral Analysis Failed",
                "description": (
                    "The ONNX model could not be behaviorally "
                    "probed. Static analysis should still be used "
                    "to assess the model."
                ),
                "layer": None,
                "evidence": {
                    "error": str(exc)
                }
            })

        return findings