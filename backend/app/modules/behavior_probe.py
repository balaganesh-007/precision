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
            "trigger_pattern": 0.1234567,
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
            raw_outputs = {}

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

                raw_outputs[probe_name] = output

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

            # Compare the trigger-pattern output against the baseline probes.
            if not findings and "trigger_pattern" in raw_outputs:
                trigger_output = raw_outputs["trigger_pattern"]

                if np.all(np.isfinite(trigger_output)):
                    baseline_outputs = []

                    for probe_name, output in raw_outputs.items():
                        if probe_name != "trigger_pattern":
                            if np.all(np.isfinite(output)):
                                baseline_outputs.append(output)

                    if baseline_outputs:
                        baseline_mean = float(
                            np.mean([
                                np.mean(output)
                                for output in baseline_outputs
                            ])
                        )

                        trigger_mean = float(
                            np.mean(trigger_output)
                        )

                        baseline_std = float(
                            np.std([
                                np.mean(output)
                                for output in baseline_outputs
                            ])
                        )

                        difference = abs(
                            trigger_mean - baseline_mean
                        )

                        evidence = {
                            "trigger_probe": "trigger_pattern",
                            "trigger_mean": trigger_mean,
                            "baseline_mean": baseline_mean,
                            "difference": difference,
                            "baseline_std": baseline_std,
                        }

                        # Flag only unusually different behavior.
                        if difference > max(
                            1.0,
                            baseline_std * 10.0
                        ):
                            findings.append({
                                "severity": "MEDIUM",
                                "title": (
                                    "Input-Specific Behavioral "
                                    "Deviation Detected"
                                ),
                                "description": (
                                    "The trigger-pattern probe produced "
                                    "an unusually different output "
                                    "compared with the baseline probes. "
                                    "This may indicate input-specific "
                                    "behavior and requires further "
                                    "investigation; it does not by itself "
                                    "prove a backdoor."
                                ),
                                "layer": input_name,
                                "evidence": evidence
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